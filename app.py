from flask import Flask, request, jsonify
import asyncio
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf.json_format import MessageToJson
import binascii
import aiohttp
import requests
import json
import like_pb2
import like_count_pb2
import uid_generator_pb2
from google.protobuf.message import DecodeError
from datetime import datetime, timedelta
import time

app = Flask(__name__)

# Constants
API_KEY = "1yearkeysforujjaiwal"
API_KEY_EXPIRY_DAYS = 366
MAX_REQUESTS = 9999
TOKENS_PER_API = 20
TOTAL_APIS = 5
MAX_LIKES = TOKENS_PER_API * TOTAL_APIS  # 100 likes

# Track API usage
api_usage = {
    "remaining_requests": MAX_REQUESTS,
    "expiry_date": datetime.now() + timedelta(days=API_KEY_EXPIRY_DAYS)
}

# Encrypt a protobuf message
def encrypt_message(plaintext):
    try:
        key = b'Yg&tc%DEuh6%Zc^8'
        iv = b'6oyZDr22E3ychjM%'
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_message = pad(plaintext, AES.block_size)
        encrypted_message = cipher.encrypt(padded_message)
        return binascii.hexlify(encrypted_message).decode('utf-8')
    except Exception as e:
        app.logger.error(f"Error encrypting message: {e}")
        return None

# Create Like protobuf message
def create_protobuf_message(user_id, region):
    try:
        message = like_pb2.like()
        message.uid = int(user_id)
        message.region = region
        return message.SerializeToString()
    except Exception as e:
        app.logger.error(f"Error creating protobuf message: {e}")
        return None

# Create UID protobuf message
def create_protobuf(uid):
    try:
        message = uid_generator_pb2.uid_generator()
        message.saturn_ = int(uid)
        message.garena = 1
        return message.SerializeToString()
    except Exception as e:
        app.logger.error(f"Error creating uid protobuf: {e}")
        return None

# Encrypt UID protobuf
def enc(uid):
    protobuf_data = create_protobuf(uid)
    if protobuf_data is None:
        return None
    encrypted_uid = encrypt_message(protobuf_data)
    return encrypted_uid

# Fetch tokens from all 5 JWT APIs
async def fetch_all_tokens():
    urls = [
        "https://free-fire-india-six.vercel.app/token",
        "https://free-fire-india-five.vercel.app/token",
        "https://free-fire-india-four.vercel.app/token",
        "https://free-fire-india-tthree.vercel.app/token",
        "https://free-fire-india-two.vercel.app/token"
    ]
    all_tokens = []
    total_tokens_generated = 0
    
    try:
        async with aiohttp.ClientSession() as session:
            tasks = [session.get(url) for url in urls]
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            
            for response in responses:
                if isinstance(response, Exception):
                    app.logger.error(f"Error fetching token: {response}")
                    continue
                if response.status != 200:
                    app.logger.error(f"Token API failed with status: {response.status}")
                    continue
                data = await response.json()
                tokens = data.get("tokens", [])
                if not tokens:
                    app.logger.error("No tokens in this response.")
                    continue
                all_tokens.extend(tokens)
                total_tokens_generated += len(tokens)

        if not all_tokens:
            app.logger.error("No tokens received from any API.")
            return None, 0
            
        return all_tokens, total_tokens_generated

    except Exception as e:
        app.logger.error(f"Error fetching tokens: {e}")
        return None, 0

# Send a single like request
async def send_request(encrypted_uid, token, url):
    try:
        edata = bytes.fromhex(encrypted_uid)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB49"
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=edata, headers=headers) as response:
                if response.status != 200:
                    app.logger.error(f"Request failed with status code: {response.status}")
                    return response.status
                return await response.text()
    except Exception as e:
        app.logger.error(f"Exception in send_request: {e}")
        return None

# Send multiple like requests (one per token)
async def send_multiple_requests(uid, server_name, url):
    try:
        region = server_name
        protobuf_message = create_protobuf_message(uid, region)
        if protobuf_message is None:
            app.logger.error("Failed to create protobuf message.")
            return None, 0, 0

        encrypted_uid = encrypt_message(protobuf_message)
        if encrypted_uid is None:
            app.logger.error("Encryption failed.")
            return None, 0, 0

        tokens, total_tokens = await fetch_all_tokens()
        if tokens is None:
            app.logger.error("Failed to load tokens from JWT APIs.")
            return None, 0, 0

        start_time = time.time()
        tasks = []
        for token in tokens:
            tasks.append(send_request(encrypted_uid, token, url))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        end_time = time.time()
        processing_time = str(timedelta(seconds=end_time-start_time)).split(".")[0]  # HH:MM:SS format
        
        # Calculate successful likes
        successful_likes = sum(1 for result in results if result is not None and not isinstance(result, Exception))
        
        return successful_likes, total_tokens, processing_time

    except Exception as e:
        app.logger.error(f"Exception in send_multiple_requests: {e}")
        return None, 0, 0

# Decode protobuf data into object
def decode_protobuf(binary):
    try:
        items = like_count_pb2.Info()
        items.ParseFromString(binary)
        return items
    except DecodeError as e:
        app.logger.error(f"Error decoding Protobuf data: {e}")
        return None
    except Exception as e:
        app.logger.error(f"Unexpected error during protobuf decoding: {e}")
        return None

# Make request to GetPlayerPersonalShow endpoint
def make_request(encrypt, server_name, token):
    try:
        if server_name == "IND":
            url = "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
        elif server_name in {"BR", "US", "SAC", "NA"}:
            url = "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
        else:
            url = "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"
        edata = bytes.fromhex(encrypt)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB49"
        }
        response = requests.post(url, data=edata, headers=headers, verify=False)
        binary = response.content
        decode = decode_protobuf(binary)
        if decode is None:
            app.logger.error("Protobuf decoding returned None.")
        return decode
    except Exception as e:
        app.logger.error(f"Error in make_request: {e}")
        return None

@app.route('/like', methods=['GET'])
def handle_requests():
    # Check API key validity
    global api_usage
    
    uid = request.args.get("uid")
    server_name = request.args.get("region", "").upper()
    key = request.args.get("key")

    if not uid or not server_name or not key:
        return jsonify({"error": "UID, region, and key are required"}), 400

    if key != API_KEY:
        return jsonify({"error": "Invalid API key"}), 403
        
    # Check remaining requests
    if api_usage["remaining_requests"] <= 0:
        return jsonify({"error": "API request limit reached"}), 429
        
    if datetime.now() > api_usage["expiry_date"]:
        return jsonify({"error": "API key expired"}), 403

    try:
        # Decrement remaining requests
        api_usage["remaining_requests"] -= 1
        
        def process_request():
            # Fetch tokens synchronously for initial info
            tokens_data = requests.get("https://free-fire-india-six.vercel.app/token").json()
            tokens_list = tokens_data.get("tokens")
            if not tokens_list:
                raise Exception("No tokens received from JWT API.")
            token = tokens_list[0]

            encrypted_uid = enc(uid)
            if encrypted_uid is None:
                raise Exception("Encryption of UID failed.")

            before = make_request(encrypted_uid, server_name, token)
            if before is None:
                raise Exception("Failed to retrieve initial player info.")
            jsone = MessageToJson(before)
            data_before = json.loads(jsone)
            before_like = int(data_before.get('AccountInfo', {}).get('Likes', 0))
            app.logger.info(f"Likes before command: {before_like}")

            # Select the like endpoint
            if server_name == "IND":
                like_url = "https://client.ind.freefiremobile.com/LikeProfile"
            elif server_name in {"BR", "US", "SAC", "NA"}:
                like_url = "https://client.us.freefiremobile.com/LikeProfile"
            else:
                like_url = "https://clientbp.ggblueshark.com/LikeProfile"

            # Send all like requests and get metrics
            successful_likes, total_tokens, processing_time = asyncio.run(
                send_multiple_requests(uid, server_name, like_url)
                
            if successful_likes is None:
                raise Exception("Failed to send like requests.")

            after = make_request(encrypted_uid, server_name, token)
            if after is None:
                raise Exception("Failed to retrieve player info after like requests.")
            jsone_after = MessageToJson(after)
            data_after = json.loads(jsone_after)
            after_like = int(data_after.get('AccountInfo', {}).get('Likes', 0))
            player_uid = int(data_after.get('AccountInfo', {}).get('UID', 0))
            player_name = str(data_after.get('AccountInfo', {}).get('PlayerNickname', ''))
            like_given = after_like - before_like
            
            # Calculate like sending process string (20+20+20+20+20 format)
            likes_per_api = [str(TOKENS_PER_API) for _ in range(TOTAL_APIS)]
            like_sending_process = "+".join(likes_per_api) + f"/{MAX_LIKES}"
            
            status = 1 if like_given != 0 else 2
            
            # Prepare response
            result = {
                "APIKeyExpiresAt": f"{API_KEY_EXPIRY_DAYS} day(s), 24 hour(s), 60 minute(s)",
                "APIKeyRemainingRequests": f"{api_usage['remaining_requests']}/{MAX_REQUESTS}",
                "LikeSendingProcess": like_sending_process,
                "TotalTokenGenerateFromJWTAPI": f"{total_tokens}/{MAX_LIKES}",
                "TotalTimeCaptureFromAllProcess": processing_time,
                "LikesGivenByAPI": like_given,
                "LikesafterCommand": after_like,
                "LikesbeforeCommand": before_like,
                "PlayerNickname": player_name,
                "UID": player_uid,
                "status": status
            }
            return result

        result = process_request()
        return jsonify(result)
    except Exception as e:
        app.logger.error(f"Error processing request: {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, use_reloader=False)