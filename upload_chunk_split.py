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
import sys


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
    for a in getAlbums(session, True):
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
def start_upload(session, photo_file_name, photo_file_name_upd, photo_file_dimension):
    session.headers["Content-Length"] = "0"
    session.headers["X-Goog-Upload-Command"] = "start"
    session.headers["X-Goog-Upload-Content-Type"] = "image/x-dcraw"  # TODO
    session.headers["X-Goog-Upload-Protocol"] = "resumable"
    session.headers["X-Goog-Upload-File-Name"] = photo_file_name_upd
    session.headers["X-Goog-Upload-Raw-Size"] = photo_file_dimension

    logging.info("start uploading photo {} -- \'{}\'".format(photo_file_dimension, photo_file_name))

    response = session.post('https://photoslibrary.googleapis.com/v1/uploads')

    del (session.headers["Content-Length"])
    del (session.headers["X-Goog-Upload-Command"])
    del (session.headers["X-Goog-Upload-Content-Type"])
    del (session.headers["X-Goog-Upload-Protocol"])
    del (session.headers["X-Goog-Upload-File-Name"])
    del (session.headers["X-Goog-Upload-Raw-Size"])

    return response


def upload_photo(session, upload_url, photo_bytes, photo_file_name, offset, chunk_granularity):
    next_chunk = offset + (int(chunk_granularity) * 4)

    if next_chunk >= len(photo_bytes):
        session.headers["X-Goog-Upload-Command"] = "upload, finalize"
    else:
        session.headers["X-Goog-Upload-Command"] = "upload"
    session.headers["X-Goog-Upload-Offset"] = str(offset)

    if next_chunk >= len(photo_bytes):
        offset_end = len(photo_bytes)
    else:
        offset_end = next_chunk

    session.headers["Content-Length"] = str(offset_end - offset)

    logging.info(
        "uploading photo {}-{}/{} [{}] -- \'{}\'".format(offset, offset_end, len(photo_bytes), offset_end - offset,
                                                         photo_file_name))
    response = session.post(upload_url, photo_bytes[offset:offset_end])

    del (session.headers["Content-Length"])
    del (session.headers["X-Goog-Upload-Command"])
    del (session.headers["X-Goog-Upload-Offset"])

    return response, next_chunk


@retry(stop_max_attempt_number=5)
def resume_photo(session, upload_url):
    session.headers["Content-Length"] = "0"
    session.headers["X-Goog-Upload-Command"] = "query"

    resume = session.post(upload_url)

    del (session.headers["Content-Length"])
    del (session.headers["X-Goog-Upload-Command"])

    response = resume.headers["X-Goog-Upload-Size-Received"]
    logging.info(f'resume from {response}')
    return response


def upload_photos():
    session = get_authorized_session('token.json')
    albums = retrieve_album(session)
    with open('upload.csv') as csv_file:

        csv_reader = csv.reader(csv_file, delimiter=',')

        for row in csv_reader:
            album_name = row[0]
            photo_file_name = row[1]
            photo_file_name_upd = str(uuid.uuid4())
            photo_file_dimension = str(os.stat(photo_file_name).st_size)
            description = row[2]
            if album_name not in albums:
                raise ValueError('cannot find album {}'.format(album_name))
            album_id = albums[album_name]

            try:
                photo_file = open(photo_file_name, mode='rb')
                photo_bytes = photo_file.read()
            except OSError as err:
                logging.error("Could not read file \'{0}\' -- {1}".format(photo_file_name, err))
                continue

            upload_token_resume = start_upload(session, photo_file_name, photo_file_name_upd, photo_file_dimension)

            if upload_token_resume.status_code == 200:
                upload_url = upload_token_resume.headers['X-Goog-Upload-URL']
                chunk_granularity = upload_token_resume.headers['X-Goog-Upload-Chunk-Granularity']
                logging.info(f'uploading url {upload_url}')

                exit_condition = False
                resume_offset = 0
                upload_token = None
                tentativo = 0

                while not exit_condition:
                    tentativo += 1
                    if tentativo == 100:
                        logging.error(f'failed load {photo_file}')
                        with open("fail.csv", "a+", newline='') as error_file:
                            error_file_writer = csv.writer(error_file, delimiter=',', quotechar='"',
                                                           quoting=csv.QUOTE_MINIMAL)
                            error_file_writer.writerow(row)
                        exit_condition = True

                    try:
                        upload_token, next_offset = upload_photo(session, upload_url, photo_bytes, photo_file_name,
                                                                 resume_offset, chunk_granularity)
                        if upload_token.status_code != 200:
                            resume_offset = resume_photo(session, upload_url)
                        else:
                            if upload_token.headers['X-Goog-Upload-Status'] != 'active':
                                exit_condition = True
                            else:
                                resume_offset = next_offset
                    except:
                        resume_offset = resume_photo(session, upload_url)

            else:
                logging.error(f'failed load {photo_file}')
                with open("fail.csv", "a+", newline='') as error_file:
                    error_file_writer = csv.writer(error_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
                    error_file_writer.writerow(row)
                continue

            if upload_token is None:
                logging.error(f'upload_token None {photo_file}')
                continue

            if (upload_token.status_code == 200) and (upload_token.content):

                create_body = json.dumps({"albumId": album_id, "newMediaItems": [
                    {"description": description, "simpleMediaItem": {"uploadToken": upload_token.content.decode()}}]},
                                         indent=4)

                resp = session.post('https://photoslibrary.googleapis.com/v1/mediaItems:batchCreate',
                                    create_body).json()

                logging.debug("Server response: {}".format(resp))

                if "newMediaItemResults" in resp:
                    status = resp["newMediaItemResults"][0]["status"]
                    if status.get("code") and (status.get("code") > 0):
                        logging.error(
                            "Could not add \'{0}\' to library -- {1}".format(os.path.basename(photo_file_name),
                                                                             status["message"]))
                    else:
                        logging.info(
                            "Added \'{}\' to library and album \'{}\' ".format(os.path.basename(photo_file_name),
                                                                               album_name))
                else:
                    logging.error(
                        "Could not add \'{0}\' to library. Server Response -- {1}".format(
                            os.path.basename(photo_file_name),
                            resp))

            else:
                logging.error(
                    "Could not upload \'{0}\'. Server Response - {1}".format(os.path.basename(photo_file_name),
                                                                             upload_token))
                with open("fail.csv", "a+", newline='') as error_file:
                    error_file_writer = csv.writer(error_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
                    error_file_writer.writerow(row)


def main():
    logging.basicConfig(format='%(asctime)s %(module)s.%(funcName)s:%(levelname)s:%(message)s',
                        datefmt='%m/%d/%Y %I_%M_%S %p',
                        # filename='log_12.log',
                        level=logging.INFO)
    # logging.getLogger().addHandler(logging.StreamHandler(sys.stdout))

    session = get_authorized_session('token.json')

    upload_photos()

    # As a quick status check, dump the albums and their key attributes

    print("{:<50} | {:>8} | {} ".format("PHOTO ALBUM", "# PHOTOS", "IS WRITEABLE?"))

    for a in getAlbums(session):
        print(
            "{:<50} | {:>8} | {} ".format(a["title"], a.get("mediaItemsCount", "0"), str(a.get("isWriteable", False))))


if __name__ == '__main__':
    main()
