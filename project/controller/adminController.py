__author__ = 'Daksh Patel'

import os

from flask import *
from werkzeug.utils import secure_filename

from project import auth
from project.model.tweetModel import *
from utils.utils import *


@app.route('/admin/fetch_annotation_overview', methods=['GET'])
@auth.login_required
def fetch_annotation_overview():
    user = g.user
    if "admin" in user.roles:
        admin = Admin()
        language = request.args.get('language')
        response = admin.fetch_annotation_by_users(lang=language)
        # print(response)
        code = 200
        status = True
        msg = f'{len(response)} users'
        result = {
            'annotation_info': response
            }
        resp = createResponse(
            status_value=status,
            code=code,
            message=msg,
            result=result
            )
        return resp
    else:
        resp = unauthorized_access()
        return resp


@app.route('/admin/fetch_reported_tweets', methods=['GET'])
@auth.login_required
def fetch_reported_tweets_admin():
    user = g.user
    if "admin" in user.roles:
        user_id = user.id
        language = request.args.get('language')
        reported_tweets = ReportedTweets.getAllReportedTweets(lang=language)
        status = True
        code = 200
        msg = f'{len(reported_tweets)} tweets found!'
        if len(reported_tweets) == 0:
            msg = 'User has not reported any tweets yet!'
        msg = msg
        result = {
            'reported_tweets': reported_tweets
            }
        resp = createResponse(
            status_value=status,
            code=code,
            message=msg,
            result=result
            )
        return resp
    else:
        resp = unauthorized_access()
        return resp


@app.route('/admin/fetch_all_annotated_tweets', methods=['GET'])
@auth.login_required
def fetch_all_annotated_tweets():
    user = g.user
    if 'admin' in user.roles:
        language = request.args.get('language')
        tweets = Tweets.objects(Q(total_annotation__gt=0) & Q(lang=language))
        tweets = json.loads(tweets.to_json())
        # print(tweets)
        # print(language, len(tweets))
        code = 200
        status = True
        msg = f'{len(tweets)} tweets found!'
        if len(tweets) == 0:
            msg = 'Annotations not started yet!'
        msg = msg
        result = {
            'tweets': tweets
            }
        resp = createResponse(
            status_value=status,
            code=code,
            message=msg,
            result=result
            )
        return resp
    else:
        resp = unauthorized_access()
        return resp


@app.route('/admin/fetch_statistics', methods=['GET'])
@auth.login_required
def fetch_statistics():
    user = g.user
    if 'admin' in user.roles:
        language = request.args.get('language')
        statistics = Admin.fetch_statistics(lang=language)
        code = 200
        status = True
        msg = f'Data received!'
        # if len(tweets) == 0:
        #     msg = 'Annotations not started yet!'
        msg = msg
        result = {
            'statistics': statistics
            }
        resp = createResponse(
            status_value=status,
            code=code,
            message=msg,
            result=result
            )
        return resp
    else:
        resp = unauthorized_access()
        return resp


@app.route('/admin/fetch_users', methods=['GET'])
@auth.login_required
def fetch_users():
    user = g.user
    print(user)
    if "admin" in user.roles:
        users = Admin.fetch_all_user()
        code = 200
        status = True
        msg = f'{len(users)} users found!'
        # if len(tweets) == 0:
        #     msg = 'Annotations not started yet!'
        msg = msg
        result = {
            'users': users
            }
        resp = createResponse(
            status_value=status,
            code=code,
            message=msg,
            result=result
            )
        return resp
    else:
        resp = unauthorized_access()
        return resp


@app.route('/admin/add_more_tweets', methods=['POST'])
@auth.login_required
def add_more_tweets():
    user = g.user
    if 'admin' in user.roles:
        admin = Admin()
        username = request.form.get('username')
        count = int(request.form.get('count'))
        language = request.form.get('language')
        # if not language:
        #     language='en'
        # print(count, type(count))
        statuses = []
        msgs = []
        result = {}
        # for username in usernames:
        #     # result[]
        status, msg = admin.add_more_tweets(username, count, lang=language)
        #
        if status:
            code = 200
            result = {}
            resp = createResponse(
                status_value=status,
                code=code,
                message=msg,
                result=result
                )
            return resp
        else:
            code = 400
            result = {}
            resp = createResponse(
                status_value=status,
                code=code,
                message=msg,
                result=result
                )
            return resp
    else:
        resp = unauthorized_access()
        return resp


@app.route('/admin/remove_tweets', methods=['POST'])
@auth.login_required
def remove_tweets():
    user = g.user
    if 'admin' in user.roles:
        username = request.form.get('username')
        count = int(request.form.get('count'))
        language = request.form.get('language')
        admin = Admin()
        status, msg = admin.remove_tweets(
            username=username,
            count=count,
            lang=language
            )
        if status:
            code = 200
            result = {}
            resp = createResponse(
                status_value=status,
                code=code,
                message=msg,
                result=result
                )
            return resp
        else:
            code = 400
            result = {}
            resp = createResponse(
                status_value=status,
                code=code,
                message=msg,
                result=result
                )
            return resp
    else:
        resp = unauthorized_access()
        return resp


@app.route('/admin/add_user', methods=['POST'])
@auth.login_required
def add_user():
    user = g.user
    if 'admin' in user.roles:
        name = request.form.get('name')
        username = request.form.get('username')
        password = request.form.get('password')
        langs = json.loads(request.form.get('languages'))
        query_set = User.objects(username=username)
        resp = None
        print(type(langs))
        print(request.data)
        print(request.get_data())
        if query_set.count() != 0:
            status = False
            code = 400
            msg = 'Username already exists!'
            result = {}
            resp = createResponse(
                status_value=status,
                code=code,
                message=msg,
                result=result
                )
        else:
            admin = Admin()
            status = admin.create_user(
                name=name,
                username=username,
                password=password,
                lang=langs
                )
            if status:
                code = 200
                result = {}
                msg = 'User added successfully!'
                resp = createResponse(
                    status_value=status,
                    code=code,
                    message=msg,
                    result=result
                    )
            else:
                code = 400
                result = {}
                msg = 'Something went wrong'
                resp = createResponse(
                    status_value=status,
                    code=code,
                    message=msg,
                    result=result
                    )
        return resp
    else:
        resp = unauthorized_access()
        return resp


@app.route('/admin/upload_more_tweets', methods=['POST'])
@auth.login_required
def upload_more_tweets():
    user = g.user
    if "admin" in user.roles:
        file_ = request.files['fileName']
        filename = secure_filename(file_.filename)
        data = file_.read().decode('utf-8')
        tmp_file_ptr = open("./tmp/{}".format(filename), 'w')
        tmp_file_ptr.write(data)
        tmp_file_name = tmp_file_ptr.name
        tmp_file_ptr.close()
        stat, write_file_name = csvToJson(tmp_file_name)
        if stat == True:
            # print("erererer")
            # print(write_file_name)
            data = json.load(open(write_file_name))
            admin = Admin()
            # print(datetime.datetime.now())
            resp = admin.upload_more_tweets(data)
            # print(datetime.datetime.now())
            if resp!=0:
                code = 200
                result = {}
                msg = f'{resp} rows added successfully!'
                resp = createResponse(
                    status_value=True,
                    code=code,
                    message=msg,
                    result=result
                    )
                # print(resp)
            else:
                os.remove(write_file_name)
                code = 201
                result = {}
                msg = "No new tweets found in the file: {}".format(filename)
                resp = createResponse(
                    status_value=True,
                    code=code,
                    message=msg,
                    result=result
                    )
                # print(resp)

            return resp
        else:
            code = 500
            result = {}
            msg = "Invalid file type or format"
            resp = createResponse(
                status_value=False,
                code=code,
                message=msg,
                result=result
                )
            return resp

    else:
        resp = unauthorized_access()
        return resp
