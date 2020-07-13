__author__ = 'Daksh Patel'

from tweepy import API
from tweepy import OAuthHandler
import json
from mongoengine import connect,Document
from credentials import creds_english
connect('english', host=f'mongodb+srv://{creds_english["username"]}:{creds_english["password"]}@hasoc-tffh8.mongodb.net/{creds_english["database"]}?retryWrites=true&w=majority&ssl=true&ssl_cert_reqs=CERT_NONE')

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


def full_tweets(client, id_list):
    directory = './tmp/'
    fname = open(directory + 'tweets.json', 'w')
    all_tweets = []
    rt_words_list = []

    for tweet_id in id_list:
        full_client = client.get_status(id=tweet_id, tweet_mode='extended')
        full_client = full_client._json
        if 'retweeted_status' in full_client:
            rt_words_list = full_client['full_text'].split(' ')[0:2]
            rt_words = ' '.join(rt_words_list)
            final_text = '{} {}'.format(rt_words, full_client['retweeted_status']['full_text'])
            full_client['full_text'] = final_text
            all_tweets.append(full_client)
        else:
            all_tweets.append(full_client)

    fname.write(json.dumps(all_tweets, indent=4))
    fname.close()

if __name__=="__main__":
    client = get_twitter_client()
    tweet_incomplete=["1126811454940823554"]
    full_tweets(client, tweet_incomplete)