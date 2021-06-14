from google.cloud import datastore
from flask import Flask, request, jsonify, make_response, _request_ctx_stack
import requests
import constants

from functools import wraps
import json

from six.moves.urllib.request import urlopen
from flask_cors import cross_origin
from jose import jwt


import json
from os import environ as env
from werkzeug.exceptions import HTTPException

from dotenv import load_dotenv, find_dotenv
from flask import redirect
from flask import render_template
from flask import session
from flask import url_for
from authlib.integrations.flask_client import OAuth
from six.moves.urllib.parse import urlencode


app = Flask(__name__)
app.secret_key = 'SECRET_KEY'
api_url = "https://final-project-ngchi.nw.r.appspot.com"
#api_url = "http://localhost:8080"


client = datastore.Client()

CLIENT_ID = 'lSVOns5Riddz8wYOQooj7mlNg7dzAQkn'
CLIENT_SECRET = '4eq-VLxsHixV-9qzw4e45FY1o0Yk1wKcguOTU6QwmZBVUamEbEUrFylcIVSpMGVf'
DOMAIN = 'final-project-ngchi.us.auth0.com'

CALLBACK_URL = api_url + '/callback'

ALGORITHMS = ["RS256"]


oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    api_base_url="https://" + DOMAIN,
    access_token_url="https://" + DOMAIN + "/oauth/token",
    authorize_url="https://" + DOMAIN + "/authorize",
    client_kwargs={
        'scope': 'openid profile email',
    },
)


# This code is adapted from https://auth0.com/docs/quickstart/backend/python/01-authorization?_ga=2.46956069.349333901.1589042886-466012638.1589042885#create-the-jwt-validation-decorator

class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code

def verify_jwt(request):
    if 'Authorization' not in request.headers:
        return AuthError({"Error": "No token."}, 401)

    auth_header = request.headers['Authorization'].split();
    token = auth_header[1]
    
    jsonurl = urlopen("https://"+ DOMAIN+"/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        return AuthError({"code": "invalid_header",
                          "description":
                              "Invalid header. "
                              "Use an RS256 signed JWT Access Token"}, 401)
    if unverified_header["alg"] == "HS256":
        return AuthError({"code": "invalid_header",
                          "description":
                              "Invalid header. "
                              "Use an RS256 signed JWT Access Token"}, 401)
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://"+ DOMAIN+"/"
            )
        except jwt.ExpiredSignatureError:
            return AuthError({"code": "token_expired",
                              "description": "token is expired"}, 401)
        except jwt.JWTClaimsError:
            return AuthError({"code": "invalid_claims",
                              "description":
                                  "incorrect claims,"
                                  " please check the audience and issuer"}, 401)
        except Exception:
            return AuthError({"code": "invalid_header",
                              "description":
                                  "Unable to parse authentication"
                                  " token."}, 401)

        return AuthError(payload, 200)
    else:
        return AuthError({"code": "no_rsa_key",
                          "description":
                              "No RSA key in JWKS"}, 401)


@app.route('/')
def home():
    return render_template('home.html')

@app.errorhandler(405)
def error_405(error):
    res = make_response(jsonify({"Error": "Request method not allowed."}))
    res.mimetype = 'application/json'
    res.status_code = 405
    return res

# User Entity
@app.route('/users', methods=['GET'])
def users_get():
    if request.method == 'GET':
        view_users = []
        query = client.query(kind=constants.users)
        results = list(query.fetch())
        for e in results:
            data = {"user_id": e["user_id"]}
            view_users.append(data)
        res = make_response(json.dumps(view_users))
        res.mimetype = 'application/json'
        res.status_code = 200
        return res

    else:
        return ('', 405)

# Non-user Entity 1
@app.route('/boats', methods=['POST', 'GET'])
def boats_post_get():
    if request.method == 'POST':
        if "application/json" in request.accept_mimetypes:
            payload = verify_jwt(request)
            if payload.status_code == 401:
                res = make_response(json.dumps(payload.error))
                res.mimetype = 'application/json'
                res.status_code = 401
                return res
            else:
                content = request.get_json()
                condition1 = "name" in content and "type" in content and "length" in content and len(content) == 3
                if condition1:
                    condition2 = type(content["name"]) is str and type(content["type"]) is str and type(content["length"]) is int
                    condition3 = content["length"] > 0
                else:
                    condition2 = False
                    condition3 = False
                if condition1 and condition2 and condition3:
                    new_boat = datastore.entity.Entity(key=client.key(constants.boats))
                    new_boat.update({"name": content["name"], "type": content["type"], "length": content["length"],
                                     "owner": payload.error["sub"], "alliance": None})
                    client.put(new_boat)
                    data = {"id": new_boat.key.id, "name": new_boat["name"], "type": new_boat["type"],
                            "length": new_boat["length"], "owner": new_boat["owner"],
                            "alliance": new_boat["alliance"], "self": api_url + "/boats/" + str(new_boat.key.id)}
                    res = make_response(json.dumps(data))
                    res.mimetype = 'application/json'
                    res.status_code = 201
                    return res
                else:
                    res = make_response(jsonify({"Error": "Invalid request body."}))
                    res.mimetype = 'application/json'
                    res.status_code = 400
                    return res
        else:
            data = {"Error": "Invalid requested media type."}
            res = make_response(json.dumps(data))
            res.mimetype = 'application/json'
            res.status_code = 406
            return res

    elif request.method == 'GET':
        if "application/json" in request.accept_mimetypes:
            payload = verify_jwt(request)
            if payload.status_code == 200:
                query = client.query(kind=constants.boats)
                query.add_filter("owner", "=", payload.error["sub"])
                q_limit = int(request.args.get('limit', 5))
                q_offset = int(request.args.get('offset', 0))
                l_iterator = query.fetch(limit=q_limit, offset=q_offset)
                pages = l_iterator.pages
                results = list(next(pages))
                if l_iterator.next_page_token:
                    next_offset = q_offset + q_limit
                    next_url = request.base_url + "?limit=" + str(q_limit) + "&offset=" + str(next_offset)
                else:
                    next_url = None
                for e in results:
                    e["id"] = e.key.id 
                    e["self"] = api_url + "/boats/" + str(e.key.id)
                output = {"boats": results, "total_number": len(list(query.fetch()))}
                if next_url:
                    output["next"] = next_url
                res = make_response(json.dumps(output))
                res.mimetype = 'application/json'
                res.status_code = 200
                return res
            else:
                return ('', 200)
        else:
            data = {"Error": "Invalid requested media type."}
            res = make_response(json.dumps(data))
            res.mimetype = 'application/json'
            res.status_code = 406
            return res

    else:
        return ('', 405)

@app.route('/boats/<boat_id>', methods=['GET', 'PUT', 'PATCH', 'DELETE'])
def boat_get_put_patch_delete(boat_id):
    if request.method == 'GET':
        if "application/json" in request.accept_mimetypes:
            payload = verify_jwt(request)
            if payload.status_code == 401:
                res = make_response(json.dumps(payload.error))
                res.mimetype = 'application/json'
                res.status_code = 401
                return res
            else:
                boat_key = client.key(constants.boats, int(boat_id))
                boat = client.get(key=boat_key)
                if boat != None:
                    if payload.error["sub"] == boat["owner"]:
                        data = {"id": boat.key.id, "name": boat["name"], "type": boat["type"],
                                "length": boat["length"], "owner": boat["owner"],
                                "alliance": boat["alliance"],"self": api_url + "/boats/" + str(boat.key.id)}
                        res = make_response(json.dumps(data))
                        res.mimetype = 'application/json'
                        res.status_code = 200
                        return res
                    else:
                        data = {"Error": "Not your boat."}
                        res = make_response(json.dumps(data))
                        res.mimetype = 'application/json'
                        res.status_code = 403
                        return res
                else:
                    data = {"Error": "Boat not found."}
                    res = make_response(json.dumps(data))
                    res.mimetype = 'application/json'
                    res.status_code = 404
                    return res
        else:
            data = {"Error": "Invalid requested media type."}
            res = make_response(json.dumps(data))
            res.mimetype = 'application/json'
            res.status_code = 406
            return res

    elif request.method == 'PUT':
        if "application/json" in request.accept_mimetypes:
            payload = verify_jwt(request)
            if payload.status_code == 401:
                res = make_response(json.dumps(payload.error))
                res.mimetype = 'application/json'
                res.status_code = 401
                return res
            else:
                content = request.get_json()
                condition1 = "name" in content and "type" in content and "length" in content and len(content) == 3
                if condition1:
                    condition2 = type(content["name"]) is str and type(content["type"]) is str and type(content["length"]) is int
                    condition3 = content["length"] > 0
                else:
                    condition2 = False
                    condition3 = False
                if condition1 and condition2 and condition3:
                    boat_key = client.key(constants.boats, int(boat_id))
                    boat = client.get(key=boat_key)
                    if boat != None:
                        if payload.error["sub"] == boat["owner"]:
                            boat.update({"name": content["name"], "type": content["type"], "length": content["length"]})
                            client.put(boat)
                            data = {"id": boat.key.id, "name": boat["name"], "type": boat["type"], 
                                    "length": boat["length"], "owner": boat["owner"], 
                                    "alliance": boat["alliance"], "self": api_url + "/boats/" + str(boat.key.id)}
                            res = make_response(json.dumps(data))
                            res.mimetype = 'application/json'
                            res.status_code = 200
                            return res
                        else:
                            data = {"Error": "Not your boat."}
                            res = make_response(json.dumps(data))
                            res.mimetype = 'application/json'
                            res.status_code = 403
                            return res
                    else:
                        data = {"Error": "Boat not found."}
                        res = make_response(json.dumps(data))
                        res.mimetype = 'application/json'
                        res.status_code = 404
                        return res
                else:
                    res = make_response(jsonify({"Error": "Invalid request body."}))
                    res.mimetype = 'application/json'
                    res.status_code = 400
                    return res
        else:
            data = {"Error": "Invalid requested media type."}
            res = make_response(json.dumps(data))
            res.mimetype = 'application/json'
            res.status_code = 406
            return res

    elif request.method == 'PATCH':
        if "application/json" in request.accept_mimetypes:
            payload = verify_jwt(request)
            if payload.status_code == 401:
                res = make_response(json.dumps(payload.error))
                res.mimetype = 'application/json'
                res.status_code = 401
                return res
            else:
                content = request.get_json()
                boat_key = client.key(constants.boats, int(boat_id))
                boat = client.get(key=boat_key)
                if boat != None:
                    if payload.error["sub"] == boat["owner"]:
                        if "name" in content:
                            if type(content["name"]) is str:
                                boat.update({"name": content["name"]})
                            else:
                                res = make_response(jsonify({"Error": "Invalid request body."}))
                                res.mimetype = 'application/json'
                                res.status_code = 400
                                return res
                        if "type" in content:
                            if type(content["type"]) is str:
                                boat.update({"type": content["type"]})
                            else:
                                res = make_response(jsonify({"Error": "Invalid request body."}))
                                res.mimetype = 'application/json'
                                res.status_code = 400
                                return res
                        if "length" in content:
                            if type(content["length"]) is int and content["length"] > 0:
                                boat.update({"length": content["length"]})
                            else:
                                res = make_response(jsonify({"Error": "Invalid request body."}))
                                res.mimetype = 'application/json'
                                res.status_code = 400
                                return res
                        client.put(boat)
                        data = {"id": boat.key.id, "name": boat["name"], "type": boat["type"], "length": boat["length"],
                                "owner": boat["owner"], "alliance": boat["alliance"], "self": api_url + "/boats/" + str(boat.key.id)}
                        res = make_response(json.dumps(data))
                        res.mimetype = 'application/json'
                        res.status_code = 200
                        return res
                    else:
                        data = {"Error": "Not your boat."}
                        res = make_response(json.dumps(data))
                        res.mimetype = 'application/json'
                        res.status_code = 403
                        return res
                else:
                    data = {"Error": "Boat not found."}
                    res = make_response(json.dumps(data))
                    res.mimetype = 'application/json'
                    res.status_code = 404
                    return res
        else:
            data = {"Error": "Invalid requested media type."}
            res = make_response(json.dumps(data))
            res.mimetype = 'application/json'
            res.status_code = 406
            return res

    elif request.method == 'DELETE':
        payload = verify_jwt(request)
        if payload.status_code == 401:
            res = make_response(json.dumps(payload.error))
            res.mimetype = 'application/json'
            res.status_code = 401
            return res
        else:
            boat_key = client.key(constants.boats, int(boat_id))
            boat = client.get(key=boat_key)
            if boat != None:
                if payload.error["sub"] == boat["owner"]:
                    if boat["alliance"] != None:
                        delete_url = api_url + "/alliances/" + str(boat["alliance"]) + "/boats/" + str(boat.key.id)
                        clear_relationship = requests.delete(delete_url)
                    client.delete(boat_key)
                    return ('', 204)
                else:
                    data = {"Error": "Not your boat."}
                    res = make_response(json.dumps(data))
                    res.mimetype = 'application/json'
                    res.status_code = 403
                    return res
            else:
                data = {"Error": "Boat not found."}
                res = make_response(json.dumps(data))
                res.mimetype = 'application/json'
                res.status_code = 404
                return res

    else:
        return ('', 405)         

# Non-user Entity 2
@app.route('/alliances', methods=['POST', 'GET'])
def alliances_post_get():
    if request.method == 'POST':
        if 'application/json' in request.accept_mimetypes:
            content = request.get_json()
            condition1 = "founding_date" in content and "PIC" in content and "capacity" in content and len(content) == 3
            if condition1:
                condition2 = type(content["founding_date"]) is str and type(content["PIC"]) is str and type(content["capacity"]) is int
                condition3 = content["capacity"] > 0
            else:
                condition2 = False
                condition3 = False
            if condition1 and condition2 and condition3:
                new_alliance = datastore.entity.Entity(key=client.key(constants.alliances))
                new_alliance.update({"founding_date": content["founding_date"], "PIC": content["PIC"], 
                                     "capacity": content["capacity"], "#boats": 0, "boats": []})
                client.put(new_alliance)
                data = {"id": new_alliance.key.id, "founding_date": new_alliance["founding_date"], 
                        "PIC": new_alliance["PIC"], "capacity": new_alliance["capacity"], "#boats": new_alliance["#boats"], 
                        "boats": new_alliance["boats"], "self": api_url + "/alliances/" + str(new_alliance.key.id)}
                res = make_response(json.dumps(data))
                res.mimetype = 'application/json'
                res.status_code = 201
                return res
            else:
                res = make_response(jsonify({"Error": "Invalid request body."}))
                res.mimetype = 'application/json'
                res.status_code = 400
                return res
        else:
            data = {"Error": "Invalid requested media type."}
            res = make_response(json.dumps(data))
            res.mimetype = 'application/json'
            res.status_code = 406
            return res

    elif request.method == 'GET':
        if "application/json" in request.accept_mimetypes:
            query = client.query(kind=constants.alliances)
            q_limit = int(request.args.get('limit', 5))
            q_offset = int(request.args.get('offset', 0))
            l_iterator = query.fetch(limit=q_limit, offset=q_offset)
            pages = l_iterator.pages
            results = list(next(pages))
            if l_iterator.next_page_token:
                next_offset = q_offset + q_limit
                next_url = request.base_url + "?limit=" + str(q_limit) + "&offset=" + str(next_offset)
            else:
                next_url = None
            for e in results:
                e["id"] = e.key.id 
                e["self"] = api_url + "/alliances/" + str(e.key.id)
            output = {"alliances": results, "total_number": len(list(query.fetch()))}
            if next_url:
                output["next"] = next_url
            res = make_response(json.dumps(output))
            res.mimetype = 'application/json'
            res.status_code = 200
            return res
        else:
            data = {"Error": "Invalid requested media type."}
            res = make_response(json.dumps(data))
            res.mimetype = 'application/json'
            res.status_code = 406
            return res

    else:
        return ('', 405)

@app.route('/alliances/<alliance_id>', methods=['GET', 'PUT', 'PATCH', 'DELETE'])
def alliance_get_put_patch_delete(alliance_id):
    if request.method == 'GET':
        if 'application/json' in request.accept_mimetypes:
            alliance_key = client.key(constants.alliances, int(alliance_id))
            alliance = client.get(key=alliance_key)
            if alliance != None:
                data = {"id": alliance.key.id, "founding_date": alliance["founding_date"],
                        "PIC": alliance["PIC"], "capacity": alliance["capacity"], "#boats": alliance["#boats"],
                        "boats": alliance["boats"], "self": api_url + "/alliances/" + str(alliance.key.id)}
                res = make_response(json.dumps(data))
                res.mimetype = 'application/json'
                res.status_code = 200
                return res
            else:
                data = {"Error": "Alliance not found."}
                res = make_response(json.dumps(data))
                res.mimetype = 'application/json'
                res.status_code = 404
                return res
        else:
            data = {"Error": "Invalid requested media type."}
            res = make_response(json.dumps(data))
            res.mimetype = 'application/json'
            res.status_code = 406
            return res

    elif request.method == 'PUT':
        if "application/json" in request.accept_mimetypes:
            content = request.get_json()
            condition1 = "PIC" in content and "capacity" in content and len(content) == 2
            if condition1:
                condition2 = type(content["PIC"]) is str and type(content["capacity"]) is int
                condition3 = content["capacity"] > 0
            else:
                condition2 = False
                condition3 = False
            if condition1 and condition2 and condition3:
                alliance_key = client.key(constants.alliances, int(alliance_id))
                alliance = client.get(key=alliance_key)
                if alliance != None:
                    if content["capacity"] >= alliance["#boats"]:
                        alliance.update({"PIC": content["PIC"], "capacity": content["capacity"]})
                        client.put(alliance)
                        data = {"id": alliance.key.id, "founding_date": alliance["founding_date"],
                                "PIC": alliance["PIC"], "capacity": alliance["capacity"], "#boats": alliance["#boats"],
                                "boats": alliance["boats"], "self": api_url + "/alliances/" + str(alliance.key.id)}
                        res = make_response(json.dumps(data))
                        res.mimetype = 'application/json'
                        res.status_code = 200
                        return res
                    else:
                        data = {"Error": "Capacity < current #boats."}
                        res = make_response(json.dumps(data))
                        res.mimetype = 'application/json'
                        res.status_code = 403
                        return res
                else:
                    data = {"Error": "Alliance not found."}
                    res = make_response(json.dumps(data))
                    res.mimetype = 'application/json'
                    res.status_code = 404
                    return res
            else:
                res = make_response(jsonify({"Error": "Invalid request body."}))
                res.mimetype = 'application/json'
                res.status_code = 400
                return res
        else:
            data = {"Error": "Invalid requested media type."}
            res = make_response(json.dumps(data))
            res.mimetype = 'application/json'
            res.status_code = 406
            return res

    elif request.method == 'PATCH':
        if "application/json" in request.accept_mimetypes:
            content = request.get_json()
            alliance_key = client.key(constants.alliances, int(alliance_id))
            alliance = client.get(key=alliance_key)
            if alliance != None:
                if "PIC" in content:
                    if type(content["PIC"]) is str:
                        alliance.update({"PIC": content["PIC"]})
                    else:
                        res = make_response(jsonify({"Error": "Invalid request body."}))
                        res.mimetype = 'application/json'
                        res.status_code = 400
                        return res
                if "capacity" in content:
                    if type(content["capacity"]) is int and content["capacity"] > 0:
                        if content["capacity"] >= alliance["#boats"]:
                            alliance.update({"capacity": content["capacity"]})
                        else:
                            res = make_response(jsonify({"Error": "Capacity < current #boats."}))
                            res.mimetype = 'application/json'
                            res.status_code = 403
                            return res
                    else:
                        res = make_response(jsonify({"Error": "Invalid request body."}))
                        res.mimetype = 'application/json'
                        res.status_code = 400
                        return res
                client.put(alliance)
                data = {"id": alliance.key.id, "founding_date": alliance["founding_date"],
                        "PIC": alliance["PIC"], "capacity": alliance["capacity"], "#boats": alliance["#boats"],
                        "boats": alliance["boats"], "self": api_url + "/alliances/" + str(alliance.key.id)}
                res = make_response(json.dumps(data))
                res.mimetype = 'application/json'
                res.status_code = 200
                return res
            else:
                data = {"Error": "Alliance not found."}
                res = make_response(json.dumps(data))
                res.mimetype = 'application/json'
                res.status_code = 404
                return res
        else:
            data = {"Error": "Invalid requested media type."}
            res = make_response(json.dumps(data))
            res.mimetype = 'application/json'
            res.status_code = 406
            return res

    elif request.method == 'DELETE':
        alliance_key = client.key(constants.alliances, int(alliance_id))
        alliance = client.get(key=alliance_key)
        if alliance != None:
            while alliance["#boats"] > 0:
                delete_url = api_url + "/alliances/" + str(alliance.key.id) + "/boats/" + str(alliance["boats"][0])
                clear_relationship = requests.delete(delete_url)
                alliance = client.get(key=alliance_key)
            client.delete(alliance_key)
            return ('', 204)
        else:
            data = {"Error": "Alliance not found."}
            res = make_response(json.dumps(data))
            res.mimetype = 'application/json'
            res.status_code = 404
            return res

    else:
        return ('', 405)

# Relationship between Non-user Entities
@app.route('/alliances/<alliance_id>/boats/<boat_id>', methods=['PUT', 'DELETE'])
def relationship_put_delete(alliance_id, boat_id):
    if request.method == 'PUT':
        payload = verify_jwt(request)
        if payload.status_code == 401:
            res = make_response(json.dumps(payload.error))
            res.mimetype = 'application/json'
            res.status_code = 401
            return res
        else:
            alliance_key = client.key(constants.alliances, int(alliance_id))
            alliance = client.get(key=alliance_key)
            boat_key = client.key(constants.boats, int(boat_id))
            boat = client.get(key=boat_key)
            if alliance != None and boat != None:
                if payload.error["sub"] == boat["owner"]:
                    if alliance["#boats"] < alliance["capacity"]:
                        if boat["alliance"] is None and int(boat_id) not in alliance["boats"]:
                            alliance["boats"].append(int(boat_id))
                            alliance["#boats"] += 1
                            client.put(alliance)
                            boat["alliance"] = int(alliance_id)
                            client.put(boat)
                            return ('', 204)
                        else:
                            data = {"Error": "Boat has an alliance already."}
                            res = make_response(json.dumps(data))
                            res.mimetype = 'application/json'
                            res.status_code = 403
                            return res
                    else:
                        data = {"Error": "Alliance is full."}
                        res = make_response(json.dumps(data))
                        res.mimetype = 'application/json'
                        res.status_code = 403
                        return res
                else:
                    data = {"Error": "Not your boat."}
                    res = make_response(json.dumps(data))
                    res.mimetype = 'application/json'
                    res.status_code = 403
                    return res
            else:
                data = {"Error": "Alliance/boat not found."}
                res = make_response(json.dumps(data))
                res.mimetype = 'application/json'
                res.status_code = 404
                return res

    elif request.method == 'DELETE':
        alliance_key = client.key(constants.alliances, int(alliance_id))
        alliance = client.get(key=alliance_key)
        boat_key = client.key(constants.boats, int(boat_id))
        boat = client.get(key=boat_key)
        if alliance != None and boat != None:
            condition1 = boat["alliance"] == int(alliance_id)
            condition2 = int(boat_id) in alliance["boats"]
            if condition1 and condition2:
                alliance["boats"].remove(int(boat_id))
                alliance["#boats"] -= 1
                client.put(alliance)
                boat["alliance"] = None
                client.put(boat)
                return ('', 204)
            else:
                data = {"Error": "Boat is not in this alliance."}
                res = make_response(json.dumps(data))
                res.mimetype = 'application/json'
                res.status_code = 403
                return res
        else:
            data = {"Error": "Alliance/boat not found."}
            res = make_response(json.dumps(data))
            res.mimetype = 'application/json'
            res.status_code = 404
            return res

    else:
        return ('', 405)

# Authentication
@app.route('/callback')
def callback_handling():
    # Handles response from token endpoint
    id_token = auth0.authorize_access_token()['id_token']
    resp = auth0.get('userinfo')
    userinfo = resp.json()
    userinfo['id_token'] = id_token

    # Store the user information in flask session.
    session['jwt_payload'] = userinfo
    session['profile'] = {
        'user_id': userinfo['sub'],
        'name': userinfo['name'],
        'jwt': userinfo['id_token'],
    }

    # Check the list of users in datastore
    create_new_user = True
    query = client.query(kind=constants.users)
    results = list(query.fetch())
    for e in results:
        if e['user_id'] == userinfo['sub']:
            create_new_user = False
            break

    # Create new user if not found
    if create_new_user:
        new_user = datastore.entity.Entity(key=client.key(constants.users))
        new_user.update({"user_id": userinfo['sub'], "name": userinfo['name']})
        client.put(new_user)

    return redirect('/dashboard')
        
@app.route('/ui_login')
def ui_login():
    return auth0.authorize_redirect(redirect_uri=CALLBACK_URL)
    
@app.route('/dashboard')
#@requires_auth
def dashboard():
    return render_template('dashboard.html',
                           userinfo=json.dumps(session['profile'], indent=4),
                           userinfo_pretty=json.dumps(session['jwt_payload'], indent=4))    

@app.route('/logout')
def logout():
    # Clear session stored data
    session.clear()
    # Redirect user to logout endpoint
    params = {'returnTo': url_for('home', _external=True), 'client_id': CLIENT_ID}
    return redirect(auth0.api_base_url + '/v2/logout?' + urlencode(params))

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)