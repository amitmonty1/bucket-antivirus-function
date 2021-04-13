import copy
import gzip
import io
import stat
import time
import urllib3
import zipfile

from datetime import datetime

import clamav
from common import *

# ENV VARIABLES
BINARIES_BUCKET = os.getenv('BINARIES_BUCKET', 'clamav-updates')
BINARIES_PATH = os.getenv('BINARIES_PATH', 'clamav/binaries')
BINARIES_KEY = os.getenv('BINARIES_KEY', 'clamav-auto.zip')

TARGET_BUCKET = os.getenv('TARGET_BUCKET')
QUARANTINE_BUCKET = os.getenv('QUARANTINE_BUCKET')

CLEAN_TAG = os.getenv('CLEAN_TAG', 'CLEAN')
INFECTED_TAG = os.getenv('INFECTED_TAG', 'INFECTED')

TARGET_SSE_KMS_KEY_ID = os.getenv('TARGET_SSE_KMS_KEY_ID')
QUARANTINE_SSE_KMS_KEY_ID = os.getenv('QUARANTINE_SSE_KMS_KEY_ID')

RETRY_THRESHOLD = int(os.getenv('RETRY_THRESHOLD', '3'))

CHAR_SCAN_RULE = os.getenv('CHAR_SCAN_RULE', 'ANY')
FILE_PACKAGING = os.getenv('FILE_PACKAGING')
ADD_ALLOWED_CHARS = os.getenv('ADD_ALLOWED_CHARS', '')

MAX_OBJECT_SIZE = os.getenv("MAX_OBJECT_SIZE")

# CONSTS
TAG_VALUE_FAILED = "FAILED"
CHAR_SCAN_RESULT_KEY = "char-scan-result"
CHAR_SCAN_TIMESTAMP_KEY = "char-scan-timestamp"

BINARIES_FAILED_TAG_VALUE = "BINARIES_FAILED"
SCAN_FAILED_TAG_VALUE = "SCAN_FAILED"
CHAR_SCAN_FAILED_TAG_VALUE = "CHAR_SCAN_FAILED"
COPY_FAILED_TAG_VALUE = "COPY_FAILED"
NOT_ALLOWED_CHARACTERS_FOUND_TAG_VALUE = "NOT_ALLOWED_CHARACTERS_FOUND"

ALLOWED_CHARS = set(range(32, 127))
ALLOWED_CHARS |= {9, 10, 13}

TAGS = {}


def add_allowed_chars():
    if len(ADD_ALLOWED_CHARS) > 0:
        add_chars = ADD_ALLOWED_CHARS.split(',')
        for char in add_chars:
            striped = char.strip()
            if len(striped) == 1:
                ALLOWED_CHARS.add(striped)
            else:
                print("Unknown character '%s' in ADD_ALLOWED_CHARS environment variable." % striped)


def open_file(local_path):
    if FILE_PACKAGING == "REGULAR":
        return io.open(local_path, 'rb')
    elif FILE_PACKAGING == "GZIP":
        return gzip.open(local_path)


def is_string_allowed(string):
    for char in string:
        if ord(char) not in ALLOWED_CHARS:
            print("Not allowed character %s, ord: %s." % (char, ord(char)))
            return False
    return True

def get_extra_args_with_acl(kms_key):
    original = get_extra_args(kms_key)
    #Bucket owner full control for cross account copy
    original['ACL'] = 'bucket-owner-full-control'
    return original

def get_extra_args(kms_key):
    return {
        'ServerSideEncryption': 'aws:kms',
        'SSEKMSKeyId': kms_key
    }

def do_char_scan(local_path):
    if CHAR_SCAN_RULE == 'ANY':
        set_status_tag_local(CHAR_SCAN_RESULT_KEY, AV_STATUS_CLEAN, CHAR_SCAN_TIMESTAMP_KEY)
        return AV_STATUS_CLEAN

    if CHAR_SCAN_RULE == 'TEXT':
        add_allowed_chars()
        num_of_characters_read = 0
        with io.BufferedReader(open_file(local_path)) as file:
            string = file.read(1000000)
            while len(string) > 0:
                num_of_characters_read += len(string)
                if not is_string_allowed(string):
                    set_status_tag_local(CHAR_SCAN_RESULT_KEY,
                                         NOT_ALLOWED_CHARACTERS_FOUND_TAG_VALUE,
                                         CHAR_SCAN_TIMESTAMP_KEY)
                    print("Not allowed character found in a string: %s" % string)
                    print("Number of characters read %s" % num_of_characters_read)
                    return NOT_ALLOWED_CHARACTERS_FOUND_TAG_VALUE
                string = file.read(1000000)
        print("Number of characters read %s" % num_of_characters_read)
        set_status_tag_local(CHAR_SCAN_RESULT_KEY, AV_STATUS_CLEAN, CHAR_SCAN_TIMESTAMP_KEY)
        return AV_STATUS_CLEAN

    raise Exception('Unknown scan type: %s' % CHAR_SCAN_RULE)
def do_copy_in_bucket(local_path, target_bucket, target_key, extra_args):
    s3_client.upload_file(
        local_path,
        target_bucket,
        target_key,
        ExtraArgs=extra_args)

    new_tags = []
    for tag_key in TAGS:
        new_tags.append({"Key": tag_key, "Value": TAGS[tag_key]})
    print("Going to apply tags on %s %s %s" % (target_bucket, target_key, new_tags))
    s3_client.put_object_tagging(
        Bucket=target_bucket,
        Key=target_key,
        Tagging={"TagSet": new_tags}
    )


def set_status_tag_local(tag_key, tag_value, tag_timestamp):
    TAGS[tag_key] = tag_value
    TAGS[tag_timestamp] = datetime.utcnow().strftime("%Y/%m/%d %H:%M:%S UTC")


def set_status_tags(bucket, key):
    print("Going to tag %s %s" % (bucket, key))
    curr_tags = s3_client.get_object_tagging(Bucket=bucket, Key=key)["TagSet"]
    new_tags = copy.copy(curr_tags)

    for tag in curr_tags:
        if tag["Key"] in TAGS:
            new_tags.remove(tag)

    for tag_key in TAGS:
        new_tags.append({"Key": tag_key, "Value": TAGS[tag_key]})
    print("Going to apply tags on %s %s %s" % (bucket, key, new_tags))
    s3_client.put_object_tagging(
        Bucket=bucket,
        Key=key,
        Tagging={"TagSet": new_tags}
    )


def set_binaries_failed_tag():
    set_status_tag_local("BINARIES", TAG_VALUE_FAILED, "binaries_timestamp")


def set_scan_failed_tag():
    set_status_tag_local("AV_SCAN", TAG_VALUE_FAILED, "av_scan_timestamp")


def set_char_scan_failed_tag():
    set_status_tag_local("CHAR_SCAN", TAG_VALUE_FAILED, "char_scan_timestamp")


def set_copy_failed_tag():
    set_status_tag_local("COPY", TAG_VALUE_FAILED, "copy_timestamp")


def log_error_and_move_file_in_quarantine(error, local_path, bucket, key, tag_action):
    print("Error report. Bucket: %s. Key: %s. Error: %s." % (bucket, key, error))
    move_file_in_quarantine(local_path, bucket, key, tag_action)


def move_file_in_quarantine(local_path, bucket, key, tag_action):
    print('Moving object in quarantine.')
    tag_action()
    target_key = get_key_with_timestamp(key)
    extra_args = get_extra_args(QUARANTINE_SSE_KMS_KEY_ID)
    do_copy_in_bucket(local_path, QUARANTINE_BUCKET, target_key, extra_args)
    s3_client.delete_object(Bucket=bucket, Key=key)
    print('Object is moved in the quarantine bucket. Object key is: \'%s\'.' % target_key)


def get_key_with_timestamp(key):
    return "%s_%s" % (key, datetime.now().strftime("%Y-%m-%d_%H:%M:%S"))


def do_with_retries(action, fail_action):
    for i in range(RETRY_THRESHOLD):
        try:
            return action()
        except Exception as e:
            print('Got the following exception: ' e)
            if i + 1 < RETRY_THRESHOLD:
                print('Current number of tries: %s of %s' % (i + 1, RETRY_THRESHOLD))
                time.sleep(min(10 * (i + 1), 30))
                continue
            else:
                print('Maximum number of tries reached: %s' % RETRY_THRESHOLD)
                fail_action(e)
                return False


def get_bucket_key_from_event(event):
    bucket = event['Records'][0]['s3']['bucket']['name']
    key = urllib.unquote_plus(event['Records'][0]['s3']['object']['key'].encode('utf8'))
    return bucket, key


def get_binaries():
    print('Checking for for binaries locally.')
    if not os.path.exists(CLAMSCAN_PATH):
        print('Binaries not found locally.')
        if not os.path.exists(CLAMAVLIB_PATH):
            os.makedirs(CLAMAVLIB_PATH)
        target_path = os.path.join('/tmp', BINARIES_KEY)
        print('Downloading binaries. '
              'Source bucket: \'%s\'. '
              'Source path:\'%s\'. '
              'Source key:\'%s\'. '
              'Target path:\'%s\''
              % (BINARIES_BUCKET, BINARIES_PATH, BINARIES_KEY, target_path))
        s3.Bucket(BINARIES_BUCKET).download_file(os.path.join(BINARIES_PATH, BINARIES_KEY), target_path)
        print('Extracting binaries from zip into \'%s\'.' % CLAMAVLIB_PATH)
        zip_ref = zipfile.ZipFile(target_path, 'r')
        zip_ref.extractall(CLAMAVLIB_PATH)
        zip_ref.close()
        files = os.listdir(CLAMAVLIB_PATH)
        for file in files:
            full_path = os.path.join(CLAMAVLIB_PATH, file)
            st = os.stat(full_path)
            os.chmod(full_path, st.st_mode | stat.S_IEXEC)
        print('\'%s\' content: %s.' % (CLAMAVLIB_PATH, files))
    else:
        print('Binaries exists locally.')
    return True


def do_scan(file_path, bucket, key):
    print('Scan object with ClamAv script.')
    start_time = datetime.utcnow()
    print("Script starting at %s\n" %
          (start_time.strftime("%Y/%m/%d %H:%M:%S UTC")))
    clamav.update_defs_from_s3(AV_DEFINITION_S3_BUCKET, AV_DEFINITION_S3_PREFIX)
    scan_result = clamav.scan_file(file_path)
    print("Scan of s3://%s resulted in %s\n" % (os.path.join(bucket, key), scan_result))
    set_status_tag_local(AV_STATUS_METADATA, scan_result, AV_TIMESTAMP_METADATA)
    print("Script finished at %s\n" %
          datetime.utcnow().strftime("%Y/%m/%d %H:%M:%S UTC"))
    return scan_result


def do_copy(scan_result, local_path, bucket, key):
    print('Preparing to copy object into target bucket: \'%s\'.' % TARGET_BUCKET)
    print('Source bucket: \'%s\', key: \'%s\'.' % (bucket, key))
    print('Current tags: %s' % TAGS)

    if scan_result == CLEAN_TAG:
        print('Object is \'%s\'. \'%s\'.' % (CLEAN_TAG, AV_STATUS_METADATA))
        extra_args = get_extra_args_with_acl(TARGET_SSE_KMS_KEY_ID)
        do_copy_in_bucket(local_path, TARGET_BUCKET, key, extra_args)
        print('Object is copied.')
    else:
        print('Object is not \'%s\'. Moving in quarantine.' % CLEAN_TAG)
        move_file_in_quarantine(local_path, bucket, key, lambda: ())
    return True


def download_file_from_s3(bucket, key):
    s3_object = s3.Object(bucket, key)
    local_path = "/tmp/%s/%s" % (bucket, key)
    create_dir(os.path.dirname(local_path))
    s3_object.download_file(local_path)
    return local_path


def remove_file(local_path):
    os.remove(local_path)


def move_big_object(bucket, key, size):
    target_key = get_key_with_timestamp(key)
    copy_source = {
        'Bucket': bucket,
        'Key': key
    }
    s3_client.copy_object(CopySource=copy_source,
                          Bucket=QUARANTINE_BUCKET,
                          Key=target_key,
                          ServerSideEncryption="aws:kms",
                          SSEKMSKeyId=QUARANTINE_SSE_KMS_KEY_ID)
    set_status_tag_local("file_too_big", size, "file_too_big_timestamp")
    set_status_tags(QUARANTINE_BUCKET, target_key)
    s3_client.delete_object(Bucket=bucket, Key=key)

 


def lambda_handler(event, context):
    bucket, key = get_bucket_key_from_event(event)

    response = s3_client.head_object(Bucket=bucket, Key=key)
    size = response['ContentLength']

    if MAX_OBJECT_SIZE and size > MAX_OBJECT_SIZE:
        print("Object is too big. Max size: %s. Actual size: %s." % (MAX_OBJECT_SIZE, size))
        move_big_object(bucket, key, size)
        return

    local_path = download_file_from_s3(bucket, key)

    TAGS.clear()
    try:
        binaries_downloaded = do_with_retries(
            lambda: get_binaries(),
            lambda error: log_error_and_move_file_in_quarantine(error, local_path, bucket, key, set_binaries_failed_tag)
        )

        if not binaries_downloaded:
            print("Filed to download binaries.")
            return

        print("Going to AV scan it")
        av_scan_result = do_with_retries(
            lambda: do_scan(local_path, bucket, key),
            lambda error: log_error_and_move_file_in_quarantine(error, local_path, bucket, key, set_scan_failed_tag)
        )

        if not av_scan_result:
            print("Scan failed.")
            return

        print("Going to char scan it")
        char_scan_result = do_with_retries(
            lambda: do_char_scan(local_path),
            lambda error: log_error_and_move_file_in_quarantine(error, local_path, bucket, key,
                                                                set_char_scan_failed_tag)
        )

        if not char_scan_result:
            print("Char scan failed")
            return

        set_status_tags(bucket, key)
        scan_result = av_scan_result if av_scan_result != AV_STATUS_CLEAN else char_scan_result
        print("Going to copy it")
        copy_result = do_with_retries(
            lambda: do_copy(scan_result, local_path, bucket, key),
            lambda error: log_error_and_move_file_in_quarantine(error, local_path, bucket, key, set_copy_failed_tag)
        )

        if not copy_result:
            print("Copy failed.")
            return

    finally:
        remove_file(local_path)