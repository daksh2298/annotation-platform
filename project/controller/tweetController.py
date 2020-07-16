__author__ = 'Daksh Patel'

from flask import *

from project import auth
from project.model.tweetModel import *
from utils.utils import *
import logtrail

msg = 'Something went wrong'


@app.route('/user/fetch_user_langs')
@auth.login_required
def fetch_user_langs():
    user = g.user
    languages = user.languages
    code = 200
    status = True
    msg = 'user has been assigned with {} languages.'.format(len(languages))
    result = {
        'languages': languages
    }
    resp = createResponse(
        status_value=status,
        code=code,
        message=msg,
        result=result
    )
    return resp


@app.route('/user/fetch_tweets')
@auth.login_required
def fetch_tweets():
    user = g.user
    language = request.args.get('language')
    tweets = user.fetch_more_tweets(lang=language)[:100]
    # print(tweets)
    if len(tweets):
        code = 200
        status = True
        msg = '{} more tweets.'.format(len(tweets))
        result = {
            'tweets': tweets,
            'total_annotated': user.total_annotated,
            'total_reported': user.total_reported,
            'agg_total': user.agg_total_assigned,
            'languages': user.languages
        }
        resp = createResponse(
            status_value=status,
            code=code,
            message=msg,
            result=result
        )
        # print(resp)
        return resp
    else:
        code = 200
        status = True
        msg = 'No more tweets assigned to you!'
        result = {
            'tweets': []
        }
        resp = createResponse(
            status_value=status,
            code=code,
            message=msg,
            result=result
        )
    return resp


@app.route('/user/annotate', methods=['POST'])
@auth.login_required
def annotate():
    user = g.user
    username = user.username
    tweet = None
    user_update = False
    tweet_update = False

    task_1 = request.form.get('task_1')
    task_2 = request.form.get('task_2')
    tweet_id = request.form.get('tweet_id')

    logtrail.Logger.info(f'Annotation attempt by {username} for id: {tweet_id}')
    curr_time_utc = datetime.datetime.utcnow()
    annotation = Annotation(
        annotator=username,
        annotated_at=curr_time_utc,
        task_1=task_1,
        task_2=task_2
    )
    user.last_active = curr_time_utc
    user_update = user.annotate_tweet(tweet_id)
    querySet = Tweets.objects(tweet_id=tweet_id)
    if querySet.count() == 1 and user_update:
        tweet = querySet[0]
        tweet_update = tweet.annotate_tweet(annotation)
    if tweet_update and user_update:
        print('going to commit!')
        user.commit_db()
        tweet.commit_db()
        resolve_conflict(user)
        status = True
        code = 200
        msg = 'Annotation successful.'
        result = {}
        resp = createResponse(
            status_value=status,
            code=code,
            message=msg,
            result=result
        )
        return resp
    else:
        resolve_conflict(user)
        status = False
        code = 400
        msg = 'Something went wrong'
        result = {}
        resp = createResponse(
            status_value=status,
            code=code,
            message=msg,
            result=result
        )
        return resp


@app.route('/user/fetch_annotation_count', methods=['GET'])
@auth.login_required
def fetch_annotation_count():
    user = g.user
    language = request.args.get('language')
    annotated_count = user.fetch_annotated_count(lang=language)
    reported_count = user.fetch_reported_count(lang=language)
    remaining_count = user.fetch_remaining_count(lang=language)
    code = 200
    status = True
    msg = '{} tweets annotated.'.format(user.total_annotated)
    result = {
        'total_annotated': annotated_count,
        'total_reported': reported_count,
        'total_remaining': remaining_count
    }
    resp = createResponse(
        status_value=status,
        code=code,
        message=msg,
        result=result
    )
    # print(resp)
    return resp


@app.route('/user/fetch_annotated_tweets', methods=['GET'])
@auth.login_required
def fetch_annotated_tweets():
    user = g.user
    request_from = request.args.get('requestFrom')
    lang = request.args.get('language')
    print(request_from)
    if request_from == 'admin':
        username = request.args.get('username')
        print('request from admin')
        user = User.objects(username=username).first()
    else:
        pass
    final_annotated_tweets = user.fetch_annotated_tweets(lang=lang)
    status = True
    code = 200
    msg = f'{len(final_annotated_tweets)} tweets found!'
    if len(final_annotated_tweets) == 0:
        msg = 'User has not started annotation yet!'
    msg = msg
    result = {
        'annotated_tweets': final_annotated_tweets
    }
    resp = createResponse(
        status_value=status,
        code=code,
        message=msg,
        result=result
    )
    return resp


@app.route('/user/fetch_reported_tweets', methods=['GET'])
@auth.login_required
def fetch_reported_tweets():
    user = g.user
    user_id = user.id
    language = request.args.get('language')
    reported_tweets = ReportedTweets.getReportedTweets(user_id, lang=language)
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


@app.route('/user/report', methods=['POST'])
@auth.login_required
def report():
    user = g.user
    print(user.name)
    user_update = False
    tweet_update = False
    tweet_id = request.form.get('tweet_id')
    tweet = Tweets.objects(tweet_id=tweet_id).first()
    if tweet:
        curr_time_utc = datetime.datetime.utcnow()
        user.last_active = curr_time_utc
        user_update = user.report_tweet(tweet_id)
        if user_update:
            user.commit_db()
            report_tweet = ReportedTweets.objects(tweet=tweet).first()
            if not report_tweet:
                report_tweet = ReportedTweets()

            report_tweet.tweet = tweet
            report_tweet.reported_by += [user]
            report_tweet.reported_at += [curr_time_utc]
            report_tweet.save()
            status = True
            code = 200
            msg = 'testing'
            result = {}
            resp = createResponse(
                status_value=status,
                code=code,
                message=msg,
                result=result
            )
            return resp

        else:
            status = False
            code = 400
            msg = 'Something went wrong'
            result = {}
            resp = createResponse(
                status_value=status,
                code=code,
                message=msg,
                result=result
            )
            return resp
    else:
        status = False
        code = 400
        msg = 'No tweet found!'
        result = {}
        resp = createResponse(
            status_value=status,
            code=code,
            message=msg,
            result=result
        )
        return resp

@app.route("/cron/keepInstanceAlive")
def keepAlive():
    status = True
    code = 200
    msg = 'Instance is alive'
    result = {}
    resp = createResponse(
        status_value=status,
        code=code,
        message=msg,
        result=result
        )
    return resp