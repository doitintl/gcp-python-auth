#!/usr/bin/env python



"""Example of calling a Google Cloud Endpoint API with a JWT signed by
a Google API Service Account."""

import argparse
import time

import google.auth.crypt
import google.auth.jwt

import requests


url = "https://oauth2.googleapis.com/token"



def generate_jwt(sa_keyfile,
                 sa_email='account@project-id.iam.gserviceaccount.com',
                 audience='your-service-name',
                 expiry_length=3600):

    """Generates a signed JSON Web Token using a Google API Service Account."""

    now = int(time.time())

    # build payload
    payload = {
        'iat': now,
        # expires after 'expirary_length' seconds.
        "exp": now + expiry_length,
        # iss must match 'issuer' in the security configuration in your
        # swagger spec (e.g. service account email). It can be any string.
        'iss': sa_email,
        "scope": "https://www.googleapis.com/auth/cloud-platform",
        # aud must be either your Endpoints service name, or match the value
        # specified as the 'x-google-audience' in the OpenAPI document.
        'aud':  'https://oauth2.googleapis.com/token',
        # sub and email should match the service account's email address
        'sub': sa_email,
        'email': sa_email
    }

    # sign with keyfile
    signer = google.auth.crypt.RSASigner.from_service_account_file(sa_keyfile)
    jwt = google.auth.jwt.encode(signer, payload)

    return jwt


def make_jwt_request(signed_jwt, url="https://oauth2.googleapis.com/token"):

    print("jwt=",signed_jwt.decode('utf-8'))

    """Makes an authorized request to the endpoint"""
    headers = {
        'Authorization': 'Bearer {}'.format(signed_jwt.decode('utf-8'))
        #'Content-Type': "application/x-www-form-urlencoded"
    }

    print("headers",headers)

    body = 'grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion={}'.format(signed_jwt.decode('utf-8'))

    print("body",body)

    response = requests.request("POST", url, data=body, headers=headers)

    response.raise_for_status()
    return response.text


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        'sa_path',
        help='The path to your service account json file.')
    parser.add_argument(
        'sa_email',
        help='The email address for the service account.')

    args = parser.parse_args()

    expiry_length = 3600
    keyfile_jwt = generate_jwt(args.sa_path,
                               args.sa_email,
                               expiry_length)

    print(make_jwt_request(keyfile_jwt))
