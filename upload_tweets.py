__author__ = 'Daksh Patel'

import json
import os

from project.model.tweetModel import Admin
from utils.utils import *

PATH = "/Users/daksh/Downloads/hindi-upload/"


def get_file_size(filename):
    return os.path.getsize(PATH + filename) / 1000000


def upload_files(path):
    files = os.listdir(PATH)
    for filename in files:
        print()
        print('-' * 50)
        filesize = get_file_size(filename)
        print(f"[INFO] Processing file: {PATH + filename}...")
        if filesize < 10:
            print(f"[INFO] Opening file: {PATH + filename}...\n"
                  f"[INFO] Size of {PATH + filename}: {filesize}")
            print(f"[INFO] Reading file...")
            file_ptr = open(PATH + filename)
            data = file_ptr.read()
            print(f"[INFO] Storing file data in {f'./tmp/{filename}'}...")
            tmp_file_ptr = open("./tmp/{}".format(filename), 'w')
            tmp_file_ptr.write(data)
            tmp_file_name = tmp_file_ptr.name
            tmp_file_ptr.close()
            print(f"[INFO] Temp file name: {tmp_file_name}...")
            stat, write_file_name = csvToJson(tmp_file_name)
            if stat == True:
                data = json.load(open(write_file_name))
                admin = Admin()
                resp = admin.upload_more_tweets(data)
                if resp != 0:
                    msg = f'{resp} rows added successfully!'
                    print(f"{'*' * 25} {msg} {'*' * 25}")
                else:
                    os.remove(write_file_name)
                    msg = "No new tweets found in the file: {}".format(filename)
                    print(f"{'*' * 25} {msg} {'*' * 25}")
            else:
                msg = "Invalid file type or format"
                print(f"{'*' * 25} {msg} {'*' * 25}")
        else:
            print(f"{'*' * 25} File size more than 10 mb {'*' * 25}")

if __name__=='__main__':
    upload_files(PATH)
