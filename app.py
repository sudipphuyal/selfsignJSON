import json
from flask import Flask, request, render_template, send_file
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
import os

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'

# Create necessary directories if they don't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Example function to fetch the private key for a given user (stored securely)
def get_private_key(user_id, passphrase):
    private_key_path = f'secure_keys/{user_id}_private_key.pem'
    with open(private_key_path, 'rb') as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=passphrase.encode(),
        )
    return private_key

# Function to fetch the public key for a given user
def get_public_key(user_id):
    public_key_path = f'public_keys/{user_id}_public_key.pem'
    with open(public_key_path, 'rb') as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())
    return public_key

@app.route('/')
def index():
    """Render the main page with forms for signing and verifying files."""
    return render_template('index.html')

@app.route('/sign_json', methods=['POST'])
def sign_json_file():
    """Sign a JSON file and embed the signature and public key in it."""
    signer = request.form.get('signer')
    passphrase = request.form.get('passphrase')
    
    if 'file' not in request.files or not signer or not passphrase:
        return "Invalid request", 400

    file = request.files['file']
    if file.filename == '':
        return "No selected file", 400

    filepath = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(filepath)

    # Load the JSON file
    with open(filepath, 'r') as json_file:
        json_data = json.load(json_file)

    # Add the signer's identifier to the JSON data
    json_data['signed_by'] = signer

    # Convert JSON data to string (canonical form for signing)
    json_string = json.dumps(json_data, sort_keys=True)

    # Get the private key of the signer
    private_key = get_private_key(signer, passphrase)

    # Sign the JSON content
    signature = private_key.sign(
        json_string.encode(),  # Sign the canonical JSON string
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    # Get the public key to include in the JSON data
    public_key = get_public_key(signer)
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    # Add the signature and public key to the JSON data
    json_data['signature'] = signature.hex()
    json_data['public_key'] = public_key_pem

    # Save the signed JSON file
    signed_json_path = os.path.join(UPLOAD_FOLDER, f'{signer}_signed_{file.filename}')
    with open(signed_json_path, 'w') as signed_json_file:
        json.dump(json_data, signed_json_file)

    return send_file(signed_json_path, as_attachment=True)

@app.route('/verify_json', methods=['POST'])
def verify_json_file():
    """Verify a signed JSON file by checking its signature and public key."""
    if 'file' not in request.files:
        return "File is missing", 400

    file = request.files['file']
    if file.filename == '':
        return "No selected file", 400

    filepath = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(filepath)

    # Read the signed JSON content
    with open(filepath, 'r') as json_file:
        signed_json_data = json.load(json_file)

    # Extract signature, public key, and original JSON data
    signer = signed_json_data.get("signed_by")
    signature = bytes.fromhex(signed_json_data.pop("signature", ""))
    public_key_pem = signed_json_data.pop("public_key", "")

    # Convert the remaining JSON data back to canonical string for verification
    json_string = json.dumps(signed_json_data, sort_keys=True)

    # Load the public key from PEM format
    public_key = serialization.load_pem_public_key(
        public_key_pem.encode(),
        backend=None
    )

    # Verify the signature
    try:
        public_key.verify(
            signature,
            json_string.encode(),  # Verify the canonical JSON string
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return f"Signature is valid. Signed by {signer}."
    except Exception as e:
        return f"Signature verification failed: {str(e)}"

if __name__ == '__main__':
    app.run(debug=True)
