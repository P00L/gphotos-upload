from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import AuthorizedSession
from google.oauth2.credentials import Credentials
import json
import os.path
import argparse
import logging
import csv
import uuid
import time
from random import randint
from retrying import retry


def parse_args(arg_input=None):
    parser = argparse.ArgumentParser(description='Upload photos to Google Photos.')
    parser.add_argument('--auth ', metavar='auth_file', dest='auth_file',
                        help='file for reading/storing user authentication tokens')
    parser.add_argument('--album', metavar='album_name', dest='album_name',
                        help='name of photo album to create (if it doesn\'t exist). Any uploaded photos will be added to this album.')
    parser.add_argument('--log', metavar='log_file', dest='log_file',
                        help='name of output file for log messages')
    parser.add_argument('photos', metavar='photo', type=str, nargs='*',
                        help='filename of a photo to upload')
    return parser.parse_args(arg_input)


def auth(scopes):
    flow = InstalledAppFlow.from_client_secrets_file(
        'credentials.json',
        scopes=scopes)

    credentials = flow.run_local_server(host='localhost',
                                        port=8080,
                                        authorization_prompt_message="",
                                        success_message='The auth flow is complete; you may close this window.',
                                        open_browser=True)

    return credentials


def get_authorized_session(auth_token_file):
    scopes = ['https://www.googleapis.com/auth/photoslibrary',
              'https://www.googleapis.com/auth/photoslibrary.sharing']

    cred = None

    if auth_token_file:
        try:
            cred = Credentials.from_authorized_user_file(auth_token_file, scopes)
        except OSError as err:
            logging.debug("Error opening auth token file - {0}".format(err))
        except ValueError:
            logging.debug("Error loading auth tokens - Incorrect format")

    if not cred:
        cred = auth(scopes)

    session = AuthorizedSession(cred)

    if auth_token_file:
        try:
            save_cred(cred, auth_token_file)
        except OSError as err:
            logging.debug("Could not save auth tokens - {0}".format(err))

    return session


def save_cred(cred, auth_file):
    cred_dict = {
        'token': cred.token,
        'refresh_token': cred.refresh_token,
        'id_token': cred.id_token,
        'scopes': cred.scopes,
        'token_uri': cred.token_uri,
        'client_id': cred.client_id,
        'client_secret': cred.client_secret
    }

    with open(auth_file, 'w') as f:
        print(json.dumps(cred_dict), file=f)


# Generator to loop through all albums

def getAlbums(session, appCreatedOnly=False):
    params = {
        'excludeNonAppCreatedData': appCreatedOnly
    }

    while True:

        albums = session.get('https://photoslibrary.googleapis.com/v1/albums', params=params).json()

        logging.debug("Server response: {}".format(albums))

        if 'albums' in albums:

            for a in albums["albums"]:
                yield a

            if 'nextPageToken' in albums:
                params["pageToken"] = albums["nextPageToken"]
            else:
                return

        else:
            return


def retrieve_album(session):
    # Find albums created by this app to see if one matches album_title
    albums = {}
    for a in getAlbums(session, False):
        albums[a["title"]] = a["id"]
    return albums


def create_or_retrieve_album(session, album_title):
    # Find albums created by this app to see if one matches album_title

    for a in getAlbums(session, True):
        if a["title"].lower() == album_title.lower():
            album_id = a["id"]
            logging.info("Uploading into EXISTING photo album -- \'{0}\'".format(album_title))
            return album_id

    # No matches, create new album

    create_album_body = json.dumps({"album": {"title": album_title}})
    # print(create_album_body)
    resp = session.post('https://photoslibrary.googleapis.com/v1/albums', create_album_body).json()

    logging.debug("Server response: {}".format(resp))

    if "id" in resp:
        logging.info("Uploading into NEW photo album -- \'{0}\'".format(album_title))
        return resp['id']
    else:
        logging.error("Could not find or create photo album '\{0}\'. Server Response: {1}".format(album_title, resp))
        return None


@retry(stop_max_attempt_number=5)
def share(session, album_id):
    session.headers["Content-type"] = "application/json"
    body = {
        "sharedAlbumOptions": {
            "isCollaborative": "true",
            "isCommentable": "true"
        }
    }

    return session.post(f'https://photoslibrary.googleapis.com/v1/albums/{album_id}:share', json.dumps(body))


def upload_photos(session):
    albums = retrieve_album(session)

    for album, album_id in albums.items():

        response = share(session, album_id)
        if response.status_code == 200:
            logging.info(
                f'{album},{response.json()["shareInfo"]["shareableUrl"]},{response.json()["shareInfo"]["shareToken"]}')
        else:
            logging.info(album)


def main():
    logging.basicConfig(format='%(asctime)s %(module)s.%(funcName)s:%(levelname)s:%(message)s',
                        datefmt='%m/%d/%Y %I_%M_%S %p',
                        filename='log.log',
                        level=logging.INFO)

    session = get_authorized_session('token.json')

    upload_photos(session)

    # As a quick status check, dump the albums and their key attributes

    # print("{:<50} | {:>8} | {} ".format("PHOTO ALBUM", "# PHOTOS", "IS WRITEABLE?"))

    # for a in getAlbums(session):
    #    print(a["title"])


if __name__ == '__main__':
    main()
