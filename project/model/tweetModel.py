__author__ = "Daksh Patel"

import datetime
import json
import os
import sys
import time
import logtrail

from flask_mongoengine import MongoEngine
from flask_security import UserMixin
from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, BadSignature, SignatureExpired)
from mongoengine import Q
# from passlib.apps import custom_app_context as pwd_context
from passlib.hash import sha256_crypt
from tweepy import OAuthHandler, API

from credentials import creds_english
from project import app
from bson import json_util

import ssl

ssl._create_default_https_context = ssl._create_unverified_context

app.config['MONGODB_SETTINGS'] = {
    'db': creds_english['database'],
    'host': f'mongodb+srv://{creds_english["username"]}:{creds_english["password"]}@hasoc-tffh8.mongodb.net/{creds_english["database"]}?retryWrites=true&w=majority&ssl=true&ssl_cert_reqs=CERT_NONE'
}

db = MongoEngine(app)


# print(db)


# noinspection PyUnresolvedReferences
class Annotation(db.EmbeddedDocument):
    annotator = db.StringField(max_length=255)
    task_1 = db.StringField(max_length=255)
    task_2 = db.StringField(max_length=255)
    annotated_at = db.DateTimeField(default=datetime.datetime.utcnow)

    def __str__(self):
        op = '{{' \
             'annotator: {0}, ' \
             'task_1: {1}, ' \
             'task_2: {2}, ' \
             'annotated_at: {3}' \
             '}}'.format(self.annotator,
                         self.task_1,
                         self.task_2,
                         self.annotated_at)

        return op


class Tweets(db.Document):
    tweet_id = db.StringField(max_length=255)
    text = db.StringField(max_length=500)
    lang = db.StringField(max_length=10, default='en')
    total_assigned = db.IntField(default=0)
    total_annotation = db.IntField(default=0)
    conflict = db.BooleanField(default=False)
    judgement = db.ListField(db.EmbeddedDocumentField(Annotation), default=[])

    # @queryset_manager
    # def objects(doc_cls, queryset):
    #     return queryset.order_by()
    def __str__(self):
        # print(hasattr(self))
        # print(getattr(self))
        op = '{{' \
             'tweet_id: {}, ' \
             'text: {}, ' \
             'lang: {}, ' \
             'total_assigned: {}, ' \
             'total_annotaton: {}, ' \
             'conflict: {}, ' \
             'judgement: {}}}'.format(self.tweet_id,
                                      self.text,
                                      self.lang,
                                      self.total_assigned,
                                      self.total_annotation,
                                      self.conflict,
                                      self.judgement)
        return op

    def commit_db(self):
        self.save()

    def check_conflict(self):
        judgements = self.judgement
        task_1 = judgements[0].task_1
        task_2 = judgements[0].task_2
        conflict = False
        for judgement in judgements[1:]:
            next_task_1 = judgement.task_1
            next_task_2 = judgement.task_2
            if task_1 != next_task_1 or task_2 != next_task_2:
                conflict = True
                break
            else:
                continue
        return conflict

    def annotate_tweet(self, annotation):
        logtrail.Logger.info(f'')
        annotators = [judgement.annotator for judgement in self.judgement]
        if annotation.annotator not in annotators:
            self.judgement.append(annotation)
            self.total_annotation += 1
            if self.total_annotation > 1:
                resp = self.check_conflict()
                if resp != self.conflict:
                    self.conflict = resp
                else:
                    pass
            else:
                pass
            # print('125 Tweets table updated successfully')
            return True
        else:
            # print('One user cannot annotate same tweet twice!')
            return False


class User(db.Document, UserMixin):
    name = db.StringField(max_length=50)
    email = db.StringField(max_length=100, default='')
    username = db.StringField(max_length=50)
    password = db.StringField(max_length=255)
    roles = db.ListField(db.StringField(), default=['annotator'])
    languages = db.ListField(db.StringField(), default=[])
    assigned_tweets = db.ListField(db.StringField(), default=[])
    annotated_tweets = db.ListField(db.StringField(), default=[])
    reported_tweets = db.ListField(db.StringField(), default=[])
    removed_tweets = db.ListField(db.StringField(), default=[])
    total_assigned = db.IntField(default=0)
    agg_total_assigned = db.IntField(default=0)
    total_annotated = db.IntField(default=0)
    total_reported = db.IntField(default=0)
    total_removed = db.IntField(default=0)
    last_active = db.DateTimeField(default=datetime.datetime.utcnow)
    active = db.BooleanField(default=True)
    auth_token = db.StringField()

    def __str__(self):
        op = '{{' \
             'name: {}, ' \
             'email: {}, ' \
             'username: {}, ' \
             'assigned_tweets: {}, ' \
             'annotated_tweets: {}, ' \
             'reported_tweets: {}, ' \
             'removed_tweets: {}, ' \
             'total_assigned: {}, ' \
             'agg_total_assigned: {}, ' \
             'total_annotated: {}, ' \
             'total_reported: {}, ' \
             'total_removed: {}, ' \
             'last_active: {}, ' \
             'active: {}' \
             '}}'.format(self.name,
                         self.email,
                         self.username,
                         self.assigned_tweets,
                         self.annotated_tweets,
                         self.reported_tweets,
                         self.removed_tweets,
                         self.total_assigned,
                         self.agg_total_assigned,
                         self.total_annotated,
                         self.total_reported,
                         self.total_removed,
                         self.last_active,
                         self.active)

        return self.username

    def commit_db(self):
        self.save()
        return True

    def hash_password(self, password):
        self.password = sha256_crypt.hash(password)

    def verify_password(self, password):
        return sha256_crypt.verify(password, self.password)

    def set_auth_token(self):
        # print('auth changed')
        s = Serializer(app.config['SECRET_KEY'], expires_in=10000000)
        self.auth_token = s.dumps({'username': self.username}).decode('utf-8')
        # print('token',self.auth_token)
        # return s.dumps({'id': str(self.id)})

    def set_new_auth_token(self):
        # print('auth changed')
        s = Serializer(app.config['SECRET_KEY'], expires_in=10000000)
        self.auth_token = s.dumps({'username': self.username}).decode('utf-8')
        self.save()

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            # print('token', token)
            data = s.loads(token)
            # print('data', data)
        except SignatureExpired as e:
            print(e)
            return None  # valid token, but expired
        except BadSignature as e:
            print(e)
            return None  # invalid token
        # print(type(ObjectId(data['id'])))
        user = User.objects.get(username=data['username'])
        # print(user.name)
        # print(token)
        # print(user.auth_token)
        if user and token == user.auth_token:
            # print(user.auth_token)
            return user
        else:
            return None

    def annotate_tweet(self, tweet_id):
        # pop the tweet id from assigned and add it into annotated
        # do the same for report as well
        if tweet_id in self.assigned_tweets and tweet_id not in self.annotated_tweets:
            self.assigned_tweets.remove(tweet_id)
            self.annotated_tweets.append(tweet_id)
            self.total_annotated += 1
            self.total_assigned -= 1
            # print('User table updated successfully')
            # resolve_conflict(self)
            return True
        else:
            if tweet_id in self.annotated_tweets:
                print('User has already annotated this tweet')
            else:
                print('This tweet is not assigned to user')
            return False

    def fetch_more_tweets(self, lang):
        # write logic for selected language
        tweets = []
        if self.total_assigned == 0:
            print('User has annotated all the tweets')
        else:
            tweet_ids = self.assigned_tweets
            tweets = Tweets.objects(Q(tweet_id__in=tweet_ids) & Q(lang=lang))
            tweets = [
                {
                    'tweet_id': tweet.tweet_id,
                    'text': tweet.text
                }
                for tweet in tweets
            ]
        return tweets
        # print(json.dumps(tweets, indent=2))

    def fetch_removed_tweets(self, lang):
        tweets = []
        if self.total_removed == 0:
            print('User has no removed tweets')
        else:
            tweet_ids = self.removed_tweets
            tweets = Tweets.objects(Q(tweet_id__in=tweet_ids) & Q(lang=lang))
            tweets = [
                {
                    'tweet_id': tweet.tweet_id,
                    'text': tweet.text
                }
                for tweet in tweets
            ]
        return tweets

    def report_tweet(self, tweet_id):
        if tweet_id in self.assigned_tweets and tweet_id not in self.annotated_tweets and tweet_id not in self.reported_tweets:
            self.assigned_tweets.remove(tweet_id)
            self.reported_tweets.append(tweet_id)
            self.total_reported += 1
            self.total_assigned -= 1
            print('User table updated successfully')
            return True
        else:
            if tweet_id in self.reported_tweets:
                print('User has already reported this tweet')
            else:
                print('This tweet is not assigned to user')
            return False

    def fetch_annotated_tweets(self, lang):
        username = self.username
        annotated_tweets_id = self.annotated_tweets
        # print(lang)
        annotated_tweets_whole = Tweets.objects(Q(tweet_id__in=annotated_tweets_id) & Q(lang=lang))
        # print(annotated_tweets_whole)
        final_annotated_tweets = []
        for tweet in annotated_tweets_whole:
            # judgement
            temp = {}
            annotation = {}
            for judgement in tweet.judgement:
                if judgement.annotator == username:
                    annotation['annotator'] = judgement.annotator
                    annotation['annotated_at'] = judgement.annotated_at
                    annotation['task_1'] = judgement.task_1
                    annotation['task_2'] = judgement.task_2
                    break
                else:
                    continue
            temp['tweet_id'] = tweet.tweet_id
            temp['text'] = tweet.text
            temp['annotation'] = annotation
            final_annotated_tweets.append(temp)
            # print(temp)
        # print(final_annotated_tweets)
        return final_annotated_tweets

    def fetch_annotated_count(self, lang):
        annotated_tweets_id = self.annotated_tweets
        # print(lang)
        annotated_tweets_whole = Tweets.objects(Q(tweet_id__in=annotated_tweets_id) & Q(lang=lang))
        annotation_count = annotated_tweets_whole.count()
        return annotation_count

    def fetch_reported_count(self, lang):
        reported_tweets_id = self.reported_tweets
        # print(lang)
        reported_tweets_whole = Tweets.objects(Q(tweet_id__in=reported_tweets_id) & Q(lang=lang))
        reported_count = reported_tweets_whole.count()
        return reported_count

    def fetch_remaining_count(self, lang):
        assigned_tweets_id = self.assigned_tweets
        # print(lang)
        assigned_tweets_whole = Tweets.objects(Q(tweet_id__in=assigned_tweets_id) & Q(lang=lang))
        assigned_count = assigned_tweets_whole.count()
        return assigned_count

    def change_password(self, new_password):
        self.hash_password(new_password)
        self.commit_db()


class ReportedTweets(db.Document):
    tweet = db.ReferenceField(Tweets)
    reported_at = db.ListField(db.DateTimeField(default=datetime.datetime.utcnow))
    reported_by = db.ListField(db.ReferenceField(User), default=[])

    @staticmethod
    def getReportedTweets(user_id, lang):
        queryset = ReportedTweets.objects(reported_by=user_id)
        reported_tweets = []
        if queryset.count():
            for obj in queryset:
                temp = {}
                if obj.tweet.lang == lang:
                    temp['tweet_id'] = obj.tweet.tweet_id
                    temp['text'] = obj.tweet.text
                    user_ids = [user.id for user in obj.reported_by]
                    time_index = user_ids.index(user_id)
                    temp['reported_at'] = obj.reported_at[time_index]
                    reported_tweets.append(temp)
                else:
                    pass
            return reported_tweets
        else:
            return reported_tweets

    @staticmethod
    def getAllReportedTweets(lang):
        queryset = ReportedTweets.objects()
        reported_tweets = []
        if queryset.count():
            for obj in queryset:
                temp = {}
                if obj.tweet.lang == lang:
                    temp['tweet_id'] = obj.tweet.tweet_id
                    temp['text'] = obj.tweet.text
                    reported_at = obj.reported_at
                    reported_by = []
                    # print(obj.reported_by)
                    for user in obj.reported_by:
                        # print(user.username)
                        reported_by.append(user.username)
                    temp['report'] = dict(zip(reported_by, reported_at))
                    reported_tweets.append(temp)
            return reported_tweets
        else:
            return reported_tweets

    def to_json(self):
        data = self.to_mongo()
        data["from_user"] = {"User": {"username": self.from_user.username}}
        return json_util.dumps(data)


class Admin:
    def distribute_all_unassigned_tweets(self, language='en', count=None, admin=False, restrict=[]):
        # TODO Double check if user has annotated the tweet of not in tweets table.
        # print('Make changes in distribution logic!! Check todo')
        # return 0
        old = 0
        new = 0
        total_assigned = 0
        update_db = False
        if admin:
            users = User.objects(Q(languages=language))
        else:
            users = User.objects(Q(languages=language) & Q(roles__ne='admin'))
        users = [user for user in users if user.username not in restrict]
        tweets_whole = Tweets.objects(Q(total_assigned__lt=2) & Q(lang=language))
        if count == None:
            count = tweets_whole.count()
        # print(users)
        # print(tweets_whole)
        total_users = len(users)
        total_tweets = len(tweets_whole[:count]) * 2
        print(total_tweets)

        tweets = list(tweets_whole[:count].values_list('tweet_id'))
        tweets += tweets
        tweet_per_user = total_tweets // total_users
        print(tweet_per_user, total_users, total_tweets)
        print(tweet_per_user)

        # print(tweet_per_user, total_users, total_tweets)
        if tweet_per_user < 1:
            tweet_per_user = 1
            total_users = total_tweets
        print(users)
        buffer = int(total_tweets - tweet_per_user * total_users)
        print(buffer)
        # i = 0

        for i in range(total_users):
            # print(users[i])
            user = users[i]
            print(user)
            if user.username in restrict:
                print('skipping user:', user.username)
                # i+=1
                continue

            # print('before', user.total_assigned)
            start = i * tweet_per_user
            end = (i + 1) * tweet_per_user
            # print(start, end)
            if buffer != 0 and i == total_users - 1:
                end = end + buffer

            assigned_tweets = list(user.assigned_tweets)
            # annotated_tweets = list(user.annotated_tweets)
            old = len(assigned_tweets)
            # print(f'starting assignment for {user.username}')
            # print(f'old {old}')
            assigned_tweets += tweets[start:end]
            # print(len(tweets[start:end]))
            # print(len(set(tweets[start:end])))
            # if 'hasoc' in assigned_tweets[0]:
            #     # print('hereee---------------'+assigned_tweets[0].split('_')[-1])
            #     time.sleep(1)
            old_annotated_reported_tweets = list(user.reported_tweets) + list(user.annotated_tweets)
            assigned_tweets = sorted(list(set(assigned_tweets)),
                                     key=lambda x: int(x.split('_')[-1]) if 'hasoc' in x else int(x))
            assigned_tweets = [tweet_id for tweet_id in assigned_tweets if
                               tweet_id not in old_annotated_reported_tweets]
            new = len(assigned_tweets)
            print(f'new {new}')
            if old < new:
                update_db = True

            if update_db:
                resp = User.objects(username=users[i].username).update(set__assigned_tweets=assigned_tweets)
                # users.reload()
                user = User.objects(username=users[i].username)[0]
                total_assigned = len(user.assigned_tweets)
                resp = User.objects(username=user.username).update(set__total_assigned=total_assigned)
                user = User.objects(username=users[i].username)[0]
                agg_total_assigned = total_assigned + user.total_annotated + user.total_reported
                resp = User.objects(username=user.username).update(set__agg_total_assigned=agg_total_assigned)
                # print(start, end)
            # print('after', total_assigned)
            # i += 1

        if update_db:
            print(len(list(set(tweets))))
            if total_users < 2:
                updated_tweets = Tweets.objects(tweet_id__in=list(set(tweets))).update(set__total_assigned=1)
                # tweets_whole[:count].update(set__total_assigned=1)
            else:
                updated_tweets = Tweets.objects(tweet_id__in=list(set(tweets))).update(set__total_assigned=2)
                # updated_tweets = tweets_whole[:count].update(set__total_assigned=2)

            print(f'Total tweets assigned {updated_tweets} (one tweet to two user) to {len(users)} users.')
            print('success')
        else:
            print('No changes to make')
        return True

    def fetch_annotation_by_users(self, lang):
        users = User.objects(Q(roles='annotator') & Q(languages=lang))
        # print(users)
        user_annots = {}
        for user in users:
            annot = {
                'task_1': {
                    'NOT': 0,
                    'HOF': 0
                },
                'task_2': {
                    'HATE': 0,
                    'OFFN': 0,
                    'PRFN': 0,
                    'NONE': 0
                }
            }
            final_annotated_tweets = user.fetch_annotated_tweets(lang=lang)
            for tweet in final_annotated_tweets:
                # print(tweet)
                # print(tweet['lang'])
                task_1 = tweet.get('annotation').get('task_1')
                task_2 = tweet.get('annotation').get('task_2')
                annot['task_1'][task_1] += 1
                annot['task_2'][task_2] += 1
            if user.total_annotated > 0:
                annot['started_annotation'] = True
            else:
                annot['started_annotation'] = False
            if user.active:
                annot['active'] = True
            else:
                annot['active'] = True
            annot['last_active'] = user.last_active
            user_annots[user.username] = annot
        # print(user_annots)
        return user_annots

    @staticmethod
    def fetch_all_user():
        users = User.objects(roles='annotator').order_by('active')
        resp = {
            'users': users
        }
        return users

    @staticmethod
    def fetch_statistics(lang):
        len_all_tweets = Tweets.objects(lang=lang).count()
        single_annotated_tweets = Tweets.objects(Q(total_annotation=1) & Q(lang=lang))
        len_single = single_annotated_tweets.count()

        double_or_more_annotated_tweets = Tweets.objects(Q(total_annotation__gt=1) & Q(lang=lang))
        len_double_more = double_or_more_annotated_tweets.count()

        len_all_reported = ReportedTweets.objects.count()

        task_1 = 0
        task_2 = 0
        # print(len_double_more)
        for tweet in double_or_more_annotated_tweets:
            temp_task_1 = []
            temp_task_2 = []
            for judgment in tweet.judgement:
                temp_task_1.append(judgment.task_1)
                temp_task_2.append(judgment.task_2)
            # print(temp_task_1, temp_task_2)
            if len(set(temp_task_1)) == 1:
                # print(task_1 + 1)
                task_1 += 1
            else:
                pass
            if len(set(temp_task_2)) == 1:
                # print(task_2 + 1)
                task_2 += 1
        if len_double_more:
            agg_task_1 = int((task_1 / len_double_more) * 100)
            agg_task_2 = int((task_2 / len_double_more) * 100)
        else:
            agg_task_1 = 0
            agg_task_2 = 0
        agreement = {
            'task_1': agg_task_1,
            'task_2': agg_task_2
        }
        resp = {
            'single_annotated': len_single,
            'double_or_more': len_double_more,
            'reported_count': len_all_reported,
            'all_tweets': len_all_tweets,
            'agreement': agreement
        }
        # print(resp)
        return resp

    def deactivate_user(self, username):
        try:
            resp = User.objects(username=username).update(set__active=False)
            return resp
        except Exception as e:
            msg = e.message
            return msg

    def reactivate_user(self, username):
        try:
            resp = User.objects(username=username).update(set__active=True)
            return resp
        except Exception as e:
            msg = e.message
            return msg

    def create_user(self, name, username, password, email='', role=None, lang=None):
        user = User()
        try:
            user.name = name
            user.email = email
            user.username = username
            # print(user.hash_password(password))
            user.set_auth_token()
            user.hash_password(password)
            if type(role) == list:
                user.roles = role
            if type(role) == str:
                user.roles.append(role)
            if type(lang) == list:
                user.languages = lang
            if type(lang) == str:
                user.languages.append(lang)
            user.save()
            return True
        except Exception as e:
            print(e)
            msg = e.message
            return msg

    def add_more_tweets(self, username, count, lang):
        old = 0
        new = 0
        total_assigned = 0
        success = False
        update_db = False
        users = User.objects(username=username)
        users_count = users.count()
        # print(lang)
        msg = ''
        if users_count == 1:
            user = users[0]
            if lang not in user.languages:
                User.objects(username=user.username).update(push__languages=lang)
            else:
                pass
            removed_tweets = [tweet['tweet_id'] for tweet in list(user.fetch_removed_tweets(lang=lang))]
            # print(removed_tweets)
            old_assigned_annotated_reported_tweets = list(user.assigned_tweets) + list(user.removed_tweets) + list(
                user.reported_tweets) + list(set(list(user.annotated_tweets) + list(
                Tweets.objects(judgement__annotator=user.username).values_list("tweet_id"))))
            # print('old_assigned_a_r_tweets', old_assigned_annotated_reported_tweets)
            old_agg_total_assigned = user.agg_total_assigned
            tweets = Tweets.objects(Q(tweet_id__nin=old_assigned_annotated_reported_tweets) & Q(lang=lang)).order_by(
                'total_assigned')
            old_assigned_tweets = list(user.assigned_tweets)
            to_be_assigned = removed_tweets[:count]
            if tweets.count():
                if len(to_be_assigned) < count:
                    # print(312)
                    diff = count - len(to_be_assigned)
                    to_be_assigned += list(tweets[:diff].values_list('tweet_id'))
                    # print('len(to_be_assigned)', len(to_be_assigned))
                # print('to be assigned', to_be_assigned)
                old = len(old_assigned_tweets) - len(list(user.reported_tweets))
                # print('old', old)
                new_assigned_tweets = old_assigned_tweets + to_be_assigned
                new_assigned_tweets = sorted(list(set(new_assigned_tweets)),
                                             key=lambda x: int(x.split('_')[-1]) if type(
                                                 x) is str and 'hasoc' in x else int(x))
                new_assigned_tweets = [str(tweet_id) for tweet_id in new_assigned_tweets]
                new = len(new_assigned_tweets)
                final_new_assigned = list(set(new_assigned_tweets) - set(old_assigned_tweets))
                # print(len(final_new_assigned), len(to_be_assigned))
                # print(final_new_assigned)
                # print(to_be_assigned)
                # print('new', new)
                new_agg_total_assigned = old_agg_total_assigned + len(to_be_assigned)

                if old < new:
                    update_db = True
                # else:
                #     update_db = False
                #     msg='User has annotated or reported all the tweets once!'

                if update_db:
                    # print(new_assigned_tweets)
                    User.objects(username=user.username).update(set__assigned_tweets=new_assigned_tweets)
                    User.objects(username=user.username).update(pull_all__removed_tweets=to_be_assigned)
                    user_updated = User.objects(username=user.username)[0]

                    total_assigned = len(user_updated.assigned_tweets)
                    old_total_removed = user_updated.total_removed
                    new_total_removed = old_total_removed - count
                    if new_total_removed < 0:
                        new_total_removed = 0
                    resp = User.objects(username=user_updated.username).update(
                        set__total_assigned=len(new_assigned_tweets))
                    resp = User.objects(username=user_updated.username).update(set__total_removed=new_total_removed)
                    user_updated = User.objects(username=user.username)[0]
                    check_db = user_updated.total_assigned + user_updated.total_annotated + user_updated.total_reported
                    # print('check_db, new_agg_total_assigned, count')
                    # print(check_db, new_agg_total_assigned, count)
                    # if new_agg_total_assigned == check_db:
                    resp = User.objects(username=user_updated.username).update(
                        set__agg_total_assigned=new_agg_total_assigned)
                    # else:
                    #     pass
                    # print('Something went wrong 338')

                    resp = Tweets.objects(tweet_id__in=to_be_assigned).update(inc__total_assigned=1)

                    # print(resp, len(to_be_assigned))
                    success = True
                    msg = f'{len(to_be_assigned)} tweets added to {username} for {lang} language.'

                else:
                    success = False
                    # print('165 something went wrong')
                    msg = f'Something went wrong.'

            else:
                success = False
                msg = f'User has already been assigned with all the tweets for {lang} language!.'

        else:
            success = False
            msg = f'Something went wrong.'

        return success, msg

    def remove_tweets(self, username, count, lang):
        # decrease assign_count in tweet table
        # remove language specific tweets
        # check if user has language assigned or not
        # add the same inverse logic to add the tweets in a language specific manner
        users = User.objects(Q(username=username) & Q(languages=lang))
        users_count = users.count()
        success = False
        msg = ''
        if users_count == 1:
            user = users[0]

            agg_total_assigned = user.agg_total_assigned
            old_assigned_tweets = [tweet['tweet_id'] for tweet in list(user.fetch_more_tweets(lang=lang))]
            old_assigned_count = len(old_assigned_tweets)
            old_removed_tweets = user.removed_tweets
            new_agg_total_assigned = agg_total_assigned - count
            if old_assigned_count == len(old_assigned_tweets):
                if count <= old_assigned_count:
                    # new_assigned_tweets = old_assigned_tweets[count:]
                    tweets_to_remove = old_assigned_tweets[:count]
                    print(tweets_to_remove)
                    count = len(tweets_to_remove)
                    updated_removed_tweets = old_removed_tweets + tweets_to_remove
                    User.objects(username=user.username).update(pull_all__assigned_tweets=tweets_to_remove)
                    user_updated = User.objects(username=user.username).first()
                    print(len(user_updated.assigned_tweets))
                    User.objects(username=user.username).update(set__total_assigned=len(user_updated.assigned_tweets))
                    User.objects(username=user.username).update(dec__agg_total_assigned=count)
                    User.objects(username=user.username).update(set__removed_tweets=updated_removed_tweets)
                    User.objects(username=user.username).update(set__total_removed=len(updated_removed_tweets))
                    Tweets.objects(tweet_id__in=tweets_to_remove).update(dec__total_assigned=1)
                    success = True
                    msg = f'{count} tweets removed from {username} for {lang} language.'

                else:
                    print('Cannot remove more than assigned')
                    success = False
                    msg = f'Cannot remove more than assigned'

            else:
                print('Something wrong with the database!')
                success = False
                msg = f'Something went wrong'
        else:
            # print(f'User not found or doesnot have {lang} assigned!')
            success = False
            msg = f'User not found or doesnot have {lang} assigned!'
        return success, msg

    def upload_more_tweets(self, data):
        tweets = []
        # print(datetime.datetime.now())
        data_unique = map(dict, set(tuple(x.items()) for x in data))
        # print(datetime.datetime.now())
        tweet_ids = set(Tweets.objects.values_list("tweet_id"))
        for datum in data_unique:
            id_str = str(datum['id_str'])
            if id_str not in tweet_ids:
                temp = {}
                temp['tweet_id'] = id_str
                temp['text'] = datum['text']
                temp['lang'] = datum['lang']
                tweets.append(Tweets(**temp))
            else:
                pass
        # tweets = list(set(tweets))
        print(len(tweets))
        if len(tweets):
            x = Tweets.objects.insert(tweets)
            x = len(x)
        else:
            x = 0
        return x


def create_dbs(users=10, tweets=100):
    User.drop_collection()
    Tweets.drop_collection()
    ReportedTweets.drop_collection()
    # Tweets.objects.insert()
    # for i in range(users):
    #     admin = Admin()
    #     if i % 2 == 0:
    #         admin.create_user(
    #             name=f'user_{i}',
    #             username=f'user_{i}',
    #             password=f'user_{i}',
    #             lang='hi'
    #             )
    #     else:
    #         admin.create_user(
    #             name=f'user_{i}',
    #             username=f'user_{i}',
    #             password=f'user_{i}',
    #             )
    admin = Admin()
    admin.create_user(
        name='Daksh Patel',
        username='daksh2298',
        password='daksh2298',
        role=['admin'],
        lang=['en', 'hi', 'de']
    )
    admin.create_user(
        name='Sandip Modha',
        username='sjmodha',
        password='sjmodha_admin@hasoc2020',
        role='admin',
        lang=['en', 'hi', 'de']
    )
    # twts = []
    # for i in range(tweets):
    #     temp = {}
    #     temp['tweet_id'] = f'{i}'
    #     temp['text'] = f'{i}_abc'
    #     temp['lang'] = 'en'
    #     # print(temp)
    #     twts.append(Tweets(**temp))
    # # print(twts)
    # x = Tweets.objects.insert(twts)
    # Tweets.save(x)
    # print('x', x)


# @app.route('/annotate')
def annotate(tweet_id='0', username='user_0'):
    # username = 'user_0'
    # tweet_id = '0'
    curr_time_utc = datetime.datetime.utcnow()
    annotation = Annotation(
        annotator=username,
        annotated_at=curr_time_utc,
        task_1='HOF',
        task_2='PRFN'
    )
    tweet = None
    user = None
    user_update = False
    tweet_update = False
    querySet = User.objects(username=username)
    if querySet.count() == 1:
        user = querySet[0]
        user.last_active = curr_time_utc
        user_update = user.annotate_tweet(tweet_id)
    else:
        pass
        # print('user not found')

    querySet = Tweets.objects(tweet_id=tweet_id)
    if querySet.count() == 1 and user_update:
        tweet = querySet[0]
        tweet_update = tweet.annotate_tweet(annotation)
    if tweet_update and user_update:
        # print('going to commit!')
        user.commit_db()
        tweet.commit_db()


def fetch_annotated_tweets():
    username = 'user_0'
    queryset = User.objects(username=username)
    if queryset.count() == 1:
        user = queryset[0]
        annotated_tweets_id = user.annotated_tweets
        annotated_tweets_whole = Tweets.objects(tweet_id__in=annotated_tweets_id)
        # print(annotated_tweets_whole)

        for tweet in annotated_tweets_whole:
            # judgement
            annotation = None
            for judgement in tweet.judgement:
                if judgement.annotator == username:
                    annotation = judgement
                    break
                else:
                    continue
            # print(tweet.tweet_id, tweet.text, annotation)
        # print(annotated_tweets_whole)


def add_new_documents(tweets=10):
    for i in range(100, 100 + tweets):
        tweet = Tweets()
        tweet.tweet_id = f'{i}'
        tweet.text = f'{i}_abc'
        tweet.lang = 'en'
        tweet.save()


def get_twitter_auth():
    consumer_key = "LvJdi0TlVRS74igPWdasrKaId"
    consumer_secret = "5NGqFoAEgUBnshE5PxSfUN4EUHBDkxNGooFSJUkEguUIZXC6Zt"
    access_key = "3192285595-O0A6RgqLSYIBN4MlIec8cxuVBUX8Y7ebFiJGze2"
    access_secret = "iFuzvAkObOvjdniIFogt0ka6DqNoTYLttS6c2C0bIOg5D"

    auth = OAuthHandler(consumer_key, consumer_secret)
    auth.set_access_token(access_key, access_secret)
    return auth


def get_twitter_client():
    auth = get_twitter_auth()
    client = API(auth, wait_on_rate_limit=True)
    return client


EXCEPTION_MESSAGE = "EXCEPTION OCCURRED! DELETE TWEET"


def full_tweets(client, id_list):
    directory = './tmp/'
    fname = open(directory + 'tweets_all.json', 'w')
    all_tweets = []
    rt_words_list = []
    fetchable = 0
    non_fetchable = 0
    i = 0
    for tweet_id in id_list:
        # print(tweet_id)
        if i % 1000 == 0:
            print(f'{i} tweets processed')
            print(f'Total Fetchable: {fetchable}')
            print(f'Total Non-Fetchable: {non_fetchable}')
        try:
            full_client = client.get_status(id=tweet_id, tweet_mode='extended')
            full_client = full_client._json
            if 'retweeted_status' in full_client:
                rt_words_list = full_client['full_text'].split(' ')[0:2]
                rt_words = ' '.join(rt_words_list)
                final_text = '{} {}'.format(rt_words, full_client['retweeted_status']['full_text'])
                full_client['full_text'] = final_text
                all_tweets.append(
                    {
                        full_client['id_str']: full_client['full_text']
                    }
                )
            else:
                all_tweets.append(
                    {
                        full_client['id_str']: full_client['full_text']
                    }
                )
            fetchable += 1
        except Exception as e:
            print(e)
            all_tweets.append(
                {
                    tweet_id: EXCEPTION_MESSAGE
                }
            )
            non_fetchable += 1
        except KeyboardInterrupt:
            fname.write(json.dumps(all_tweets, indent=2))
            fname.close()
            print(f'{i} tweets processed')
            print(f'Total Fetchable: {fetchable}')
            print(f'Total Non-Fetchable: {non_fetchable}')
            try:
                sys.exit(0)
            except SystemExit:
                os._exit(0)
        i += 1

    fname.write(json.dumps(all_tweets, indent=2))
    fname.close()
    return all_tweets


def fetch_incomplete_tweets_db():
    tweets = Tweets.objects(text__contains="…")
    tweets = [tweet for tweet in tweets if len(tweet.text) > 135]
    print(len(tweets))
    tweet_incomplete = []
    counts = {}
    for tweet in tweets:
        length = len(tweet.text)
        if length > 135:
            tweet_incomplete.append(
                {
                    'tweet_id': tweet.tweet_id,
                    'text': tweet.text
                }
            )
        if length in counts:
            counts[length] += 1
        else:
            counts[length] = 1
    # print(counts)
    # print(tweet_incomplete)
    return tweet_incomplete


def read_fetched_tweets():
    file_ptr = open('./tmp/tweets.json')
    data = json.load(file_ptr)
    return data


def resolve_conflict(user):
    user_annotated = set(user.annotated_tweets)
    temp = list(set(list(user.annotated_tweets) + list(
        Tweets.objects(judgement__annotator=user.username).values_list("tweet_id"))))
    actual_annotated = set(Tweets.objects(judgement__annotator=user.username).values_list("tweet_id"))
    difference_annotated = list(actual_annotated.difference(user_annotated))

    print(actual_annotated.intersection(set(user.assigned_tweets)))
    print(len(user_annotated.intersection(actual_annotated)),
          len(actual_annotated.difference(user_annotated)),
          len(user_annotated.difference(actual_annotated)))

    if len(actual_annotated.difference(user_annotated)):
        print(f'resolving issue for {user.name}')

        old_total_annotated = user.total_annotated
        old_total_assigned = user.total_assigned
        old_agg_total_assigned = user.agg_total_assigned
        User.objects(username=user.username).update(annotated_tweets=actual_annotated)
        User.objects(username=user.username).update(inc__total_annotated=len(difference_annotated))
        User.objects(username=user.username).update(pull_all__assigned_tweets=difference_annotated)
        User.objects(username=user.username).update(dec__total_assigned=len(difference_annotated))
        User.objects(username=user.username).update(dec__agg_total_assigned=len(difference_annotated))
        user_updated = User.objects(username=user.username).first()

        if old_total_annotated + len(difference_annotated) == user_updated.total_annotated:
            print("Total annotated checked")
        else:
            print('Values did not match for total annotated', old_total_annotated + len(difference_annotated),
                  user_updated.total_annotated)

        if old_total_assigned - len(difference_annotated) == user_updated.total_assigned:
            print("Total assigned checked")
        else:
            print('Values did not match for total assigned', old_total_assigned - len(difference_annotated),
                  user_updated.total_assigned)

        if old_agg_total_assigned - len(difference_annotated) == user_updated.agg_total_assigned:
            print("agg_total_assigned checked")
        else:
            print('Values did not match for agg total assigned', old_agg_total_assigned - len(difference_annotated),
                  user_updated.agg_total_assigned)

        user_annotated = set(user_updated.annotated_tweets)
        print(len(user_annotated.intersection(actual_annotated)),
              len(actual_annotated.difference(user_annotated)),
              len(user_annotated.difference(actual_annotated)))



if __name__ == '__main__':
    # username = 'user_3'
    # create_dbs(users=7, tweets=100)
    # user=User.objects(username="sjmodha").first()
    # user.change_password("sjmodha_admin@hasoc2020")
    # print(user.verify_password("sjmodha_admin@hasoc2020"))
    # tweets_ids=[tweet_id for tweet_id in Tweets.objects(lang='hi').values_list("tweet_id")[:100]]
    # print(len(tweets_ids))
    admin = Admin()
    for user in admin.fetch_all_user():
        print(user.username)
        resolve_conflict(user)
    # for user in admin.fetch_all_user():
    #     print(user.username)
    #     intersect=set(user.assigned_tweets).intersection(tweets_ids)
    #     print(intersect)
    #     User.objects(username=user.username).update(pull_all__assigned_tweets=list(intersect))
    #     User.objects(username=user.username).update(dec__total_assigned=len(intersect))
    #     User.objects(username=user.username).update(dec__agg_total_assigned=len(intersect))
    # for user in admin.fetch_all_user():
    #     print(user.username)
    #     print("annotated check",len(user.annotated_tweets)==user.total_annotated)
    #     print("assigned check",len(user.assigned_tweets)==user.total_assigned)
    #     print("annotated check",len(user.reported_tweets)==user.total_reported)
    # if user.assigned_tweets
    # admin.distribute_all_unassigned_tweets("hi", count=4900, admin=True,
    #                                        restrict=['sjmodha', 'mohana_dave', 'daksh2298', 'thomas_m'])
    # client = get_twitter_client()
    # # tweets_incomplete = fetch_incomplete_tweets_db()
    # tweet_incomplete = Tweets.objects().all().values_list("tweet_id")
    # print(tweet_incomplete)
    #
    # full_tweets_text = full_tweets(client, tweet_incomplete)
    # tweets_hi=Tweets.objects(lang='hi')
    # count=0
    # for tweet in tweets_hi:
    #     count+=1
    #     print(tweet.tweet_id)
    #     tweet.delete()
    # print(count)

    # # full_tweets_text = read_fetched_tweets()
    # # change_track = {True: 0, False: 0}
    # print(len(full_tweets_text),len(tweets_incomplete))
    # actual_count=0
    # exception_count=0
    # did_not_match_count=0
    # for i in range(len(full_tweets_text)):
    #     if full_tweets_text[i]!=EXCEPTION_MESSAGE:
    #         # print(tweets_incomplete[i]['text'].startswith(tweets_incomplete[:100]))
    #         # print(full_tweets_text[i].startswith(tweets_incomplete[i]['text'][:100]))
    #         if full_tweets_text[i].startswith(tweets_incomplete[i]['text'][:50]):
    #             actual_count+=1
    #         else:
    #             print(tweets_incomplete[i]['text'])
    #             print(full_tweets_text[i])
    #             print()
    #             did_not_match_count+=1
    #     else:
    #         exception_count+=1
    # print(actual_count,exception_count,did_not_match_count)
    #     if tweets_text[i] != full_tweets_text[i]:
    #         pass
    # print(change_track)
    # id_list=["1126811454940823554"]
    # full_tweets(client,id_list)

    # admin.create_user(
    #     name='Kanishka Chetia',
    #     username='kanishka_chetia',
    #     password='kanishka_chetia',
    #     lang=['en']
    #     )

    # #     if 'de' in user.languages and user.username not in ['sjmodha','mohana_dave']:
    #

    # resolve clashes code till 1129
    # for user in admin.fetch_all_user():
    #     print(user.name)
    #     # print(len(user.assigned_tweets), user.total_assigned)
    #     # print(len(user.annotated_tweets), user.total_annotated)
    #     # print(len(user.reported_tweets), user.total_reported)
    #     # print(user.agg_total_assigned)
    #     # user=User.objects(username='mohana_dave').first()
    #     resolve_conflict()
    # for user in admin.fetch_all_user():
    #     print(user.username)
    #     print("annotated check",len(user.annotated_tweets)==user.total_annotated)
    #     print("assigned check",len(user.assigned_tweets)==user.total_assigned)
    #     print("annotated check",len(user.reported_tweets)==user.total_reported)
    # print("annotated list len:",len(user.annotated_tweets))
    # print("annotated count:",user.total_annotated)
    #
    # print("assigned list len:",len(user.assigned_tweets))
    # print("assigned count:",user.total_assigned)
    #
    # print("reported list len:",len(user.reported_tweets))
    # print("reported count:",user.total_reported)

    #         # tweets_to_remove = list(set(user.assigned_tweets).intersection(set(user.annotated_tweets)))
    #         # print("conflict", len(tweets_to_remove))
    #         User.objects(username=user.username).update(assigned_tweets=[])
    #         user_updated = User.objects(username=user.username).first()
    #         print(len(user_updated.assigned_tweets))
    #         User.objects(username=user.username).update(set__total_assigned=len(user_updated.assigned_tweets))
    #         User.objects(username=user.username).update(set__agg_total_assigned=len(user_updated.assigned_tweets))
    #         print(user.name)
    #         print(len(user.assigned_tweets), user.total_assigned)
    #         print(len(user.annotated_tweets), user.total_annotated)
    #         print(len(user.reported_tweets), user.total_reported)
    #         print(user.agg_total_assigned)
    # Tweets.objects(lang="de").update(set__total_assigned=0)

    # admin.create_user(
    #     name='Thomas Mandl',
    #     username='thomas_m',
    #     password='thomas_admin@hasoc2020',
    #     role='admin',
    #     lang=['en', 'hi', 'de']
    #     )
    # admin.remove_tweets(username='sjmodha', count=1, lang='hi')
    # admin.add_more_tweets(username='sjmodha', count=3, lang='hi')

    # file_ptr = open('./merge_hindi.json')
    # data = json.loads(file_ptr.read())
    # resp = admin.upload_more_tweets(data)
    # print(resp, 'Tweets added')
    # file_ptr = open('./merge_test_en.json')
    # data = json.loads(file_ptr.read())
    # resp = admin.upload_more_tweets(data)
    # print(resp, 'Tweets added')
    # admin.distribute_all_unassigned_tweets(language='hi')
    # admin.distribute_all_unassigned_tweets(language='en')
    # # admin.remove_tweets(username,10)
    # # admin.add_more_tweets(username=username, count=12)
    # # for i in range(5):
    # #     annotate(tweet_id=str(i), username=username)
    # fetch_annotated_tweets()

    # add_new_documents(tweets=2)
    # admin.distribute_all_unassigned_tweets(language='en')
    # fetch_more_tweets()
    # User.remove_tweets(username='user_0', count=10)
    # User.add_more_tweets(username='user_0', count=5)
    # User.add_more_tweets(username='user_0', count=10)
    # create class admin with all the admin functionalities like add remove user n all
    # Creating user and making annotation
    # annotate()
    # username = 'user_0'
    # tweet_id = '100'
    # curr_time_utc = datetime.datetime.utcnow()
    # annotation = Annotation()
    # annotation.annotator = username
    # annotation.annotated_at = curr_time_utc
    # annotation.task_1 = 'HOF'
    # annotation.task_2 = 'OFF'
    # # print(annotation)
    # tweet = None
    # user = None
    # user_update = False
    # tweet_update = False
    # querySet = User.objects(username=username)
    # if querySet.count() == 1:
    #     user = querySet[0]
    #     # print(user)
    #     user.last_active = curr_time_utc
    #     user_update = user.annotate_tweet(tweet_id)
    # else:
    #     print('user not found')
    #
    # querySet = Tweets.objects(tweet_id=tweet_id)
    # if querySet.count() == 1 and user_update:
    #     tweet = querySet[0]
    #     # print(tweet)
    #     tweet_update = tweet.annotate_tweet(annotation)
    # #
    # if tweet_update and user_update:
    #     print('going to commit!')
    #     user.commit_db()
    #     tweet.commit_db()

    # for i in range(10):
    #     user = User()
    #     user.create_user(name=f'user_{i}', username=f'user_{i}', password=f'user_{i}')
    # user = User()
    # user.deactivate_user(username='user1')
    # user.create_user(name='user1', username='user1', password='user1')
    # user.name = 'Daksh'
    # user.username = 'daksh2298'
    # user.password = 'daksh2298'
    # user.assigned_tweets+=['10', '11']
    # user.annotated_tweets+=['10']
    # user.reported_tweets+=['11']
    # user.total_annotated = 1
    # user.save()
    # annotation=Annotation()
    # annotation.annotator='daksh2298'
    # annotation.task_1='NOT'
    # annotation.task_2='PRFN'
    # # annotation.save()
    # for i in range(0, 100):
    #     tweet = Tweets()
    #     # tweet=Tweets.objects(tweet_id='123')[0]
    #     tweet.tweet_id = f'{i}'
    #     tweet.text = f'{i}_abc'
    #     tweet.lang = 'en'
    #     # tweet.total_annotation+=1
    #     # tweet.judgement.append(annotation)
    #     tweet.save()
    # tweet = Tweets.objects(judgement__annotator="daksh2298")
    # print(tweet[0].text)

# assigned_tweets=user.assigned_tweets
#     assigned_tweets.append('10','11')
#     annotated_tweets=user.annotated_tweets
#     annotated_tweets.append('10','11')
#     reported_tweets=user.reported_tweets
#     reported_tweets.append('10','11')
#     user.assigned_tweets=assigned_tweets
#     user.annotated_tweets=annotated_tweets
#     user.reported_tweets=reported_tweets
#     user.total_annotated = 1
