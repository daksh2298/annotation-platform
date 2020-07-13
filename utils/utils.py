__author__ = "Daksh Patel"

import datetime
import pandas as pd

from flask import jsonify


def createResponse(status_value, code, message, result=None):
    if result is None:
        result = {}
    resp = {
        'status': status_value,
        'code': code,
        'message': message,
        'result': result,
        'version': 'v5.1'
        }
    # print(json.dumps(resp, indent=2))
    resp = jsonify(resp)
    resp.headers.add('Access-Control-Allow-Origin', '*')
    return resp


def unauthorized_access(code=401, status=False, msg=f'Unauthorized access to admin resources'):
    result = {}
    resp = createResponse(
        status_value=status,
        code=code,
        message=msg,
        result=result
        )
    return resp


def get_time_string():
    return str(datetime.datetime.now()).split('.')[0].replace("-", "_").replace(" ", "_").replace(":", "_")


def csvToJson(filename):
    try:
        lang = None
        write_file = "./dataset/"
        if filename.find("en") != -1:
            lang = "en"
            write_file += lang
        elif filename.find("hi") != -1:
            lang = "hi"
            write_file += lang
        elif filename.find("Ge") != -1 or filename.find("de") != -1:
            lang = "de"
            write_file += lang
        df = pd.read_csv(filename)
        # print(df.columns)
        df = df[['id', 'text']]
        # print(df.columns)
        curr_time_str = get_time_string()
        write_file += "/{}.json".format(curr_time_str)
        df.columns = ["id_str", "text"]
        df = df.drop_duplicates("id_str")
        lang_li = [lang] * len(df)
        df['lang'] = lang_li
        df[["id_str", "text", 'lang']].to_json(write_file, orient="records", default_handler=list, indent=2)
        return True, write_file
    except Exception as e:
        msg=None
        if hasattr(e, 'message'):
            print(e.message)
            msg=e.message
        else:
            print(e)
            msg=e
        return False, msg
