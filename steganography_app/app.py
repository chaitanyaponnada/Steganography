import os
import shutil
from stegano import lsb
from PIL import Image
from pydub import AudioSegment
from flask import Flask, request, Response, render_template, send_file, redirect, url_for, session
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import subprocess


app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

UPLOAD_FOLDER = 'uploads'
STATIC_FOLDER = 'static'
MAPPINGS_FOLDER = 'mappings'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'bmp', 'gif', 'mp4', 'avi', 'mov', 'mkv', 'wav', 'mp3', 'flac', 'txt'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['STATIC_FOLDER'] = STATIC_FOLDER
app.config['MAPPINGS_FOLDER'] = MAPPINGS_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def clear_static_folder():
    for filename in os.listdir(app.config['STATIC_FOLDER']):
        file_path = os.path.join(app.config['STATIC_FOLDER'], filename)
        try:
            if os.path.isfile(file_path) or os.path.islink(file_path):
                os.unlink(file_path)
            elif os.path.isdir(file_path):
                shutil.rmtree(file_path)
        except Exception as e:
            print(f"Failed to delete {file_path}. Reason: {e}")

def clear_uploads_folder():
    for filename in os.listdir(app.config['UPLOAD_FOLDER']):
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        try:
            if os.path.isfile(file_path) or os.path.islink(file_path):
                os.unlink(file_path)
            elif os.path.isdir(file_path):
                shutil.rmtree(file_path)
        except Exception as e:
            print(f"Failed to delete {file_path}. Reason: {e}")
# Database setup
def init_db():
    with sqlite3.connect('users.db') as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                decode_pin TEXT NOT NULL
            )
        ''')
        conn.commit()

init_db()

@app.route('/')
def index():
    if 'username' in session:
        return render_template('index.html', logged_in=True)
    return render_template('index.html', logged_in=False)

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    with sqlite3.connect('users.db') as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT password FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()

    if user:
        stored_password_hash = user[0]
        print(f"Username entered: {username}")
        print(f"User fetched from DB: {user}")
        print(f"Stored hash: {stored_password_hash}")
        
        # Debug: Manually hash the input password and compare
        
        if check_password_hash(stored_password_hash, password):
            session['username'] = username
            return redirect(url_for('index')) and "Login successful"
        else:
            print("Password does not match.")
            return 'Login failed. Please check your credentials.'
    else:
        print("No user found with that username.")
        return 'Login failed. Please check your credentials.'
@app.route('/logout', methods=['POST'])
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))

@app.route('/register', methods=['POST'])
def register():
    username = request.form.get('username')
    password = request.form.get('password')
    decode_pin = request.form.get('decode_pin')

    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

    with sqlite3.connect('users.db') as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT username FROM users WHERE username = ?', (username,))
        if cursor.fetchone():
            return 'Username already exists. Please choose a different one.'

        cursor.execute('INSERT INTO users (username, password, decode_pin) VALUES (?, ?, ?)', 
                       (username, hashed_password, decode_pin))
        conn.commit()

    return redirect(url_for('index'))

@app.route('/validate-pin', methods=['POST'])
def validate_pin():
    if 'username' not in session:
        return Response('Not logged in', status=403, mimetype='text/plain')
     
    data = request.get_json()
    pin = data.get('pin')

    if  not pin:
        return Response('PIN are required', status=400, mimetype='text/plain')
    
    username = session.get('username')

    with sqlite3.connect('users.db') as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT decode_pin FROM users WHERE username = ?', (username,))
        row = cursor.fetchone()

    if row and row[0] == pin:
        return Response('valid', status=200, mimetype='text/plain')
    else:
        return Response('invalid', status=401, mimetype='text/plain')



@app.route('/select/<steganography_type>', methods=['GET'])
def select(steganography_type):
    if steganography_type not in ['image', 'audio', 'text']:
        return redirect(url_for('index'))
    return render_template('select.html', steganography_type=steganography_type)

@app.route('/encode', methods=['POST'])
def encode():
    print(request.form)
    steganography_type = request.form['type']
    file = request.files['file']
    message = request.form['message']
    save_path = request.form.get('save_path', '').strip()

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)

        encoded_file_path = None
        pass_key = None

        # Process encoding based on type
        if steganography_type == 'image':
            encoded_file_path = encode_image(file_path, message)
        elif steganography_type == 'video':
            encoded_file_path, pass_key = encode_video(file_path, message)
        elif steganography_type == 'audio':
            encoded_file_path = encode_audio(file_path, message)
        elif steganography_type == 'text':
            encoded_file_path = encode_text(file_path, message)

        # Save the encoded file to the specified path
        if save_path and encoded_file_path:
            if not os.path.isabs(save_path):
                save_path = os.path.join(app.config['UPLOAD_FOLDER'], save_path)
            os.makedirs(os.path.dirname(save_path), exist_ok=True)
            os.rename(encoded_file_path, save_path)
            encoded_file_path = save_path

        # If video, show pass key in result.html
        if steganography_type == 'video' and pass_key is not None:
            return render_template('result.html', pass_key=pass_key, file_path=encoded_file_path)

        # For other types, download the file directly
        if encoded_file_path:
            return send_file(encoded_file_path, as_attachment=True)

    return 'Invalid file type or no file uploaded.'

@app.route('/download', methods=['GET'])
def download_file():
    file_path = request.args.get('file_path', None)
    if file_path :
        return send_file(file_path, as_attachment=True)
    return 'File not found.'

@app.route('/decode', methods=['POST'])
def decode():
    steganography_type = request.form['type']
    file = request.files['file']

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)

        if steganography_type == 'image':
            message = decode_image(file_path)
        elif steganography_type == 'video':
            message = decode_video(file_path)
        elif steganography_type == 'audio':
            message = decode_audio(file_path)
        elif steganography_type == 'text':
            message = decode_text(file_path)

        clear_static_folder()
        clear_uploads_folder()

        return render_template('result.html', message=message, steganography_type=steganography_type)
    

# Image Steganography
def gen_data(data):
    newd = []
    for i in data:
        newd.append(format(ord(i), '08b'))
    return newd

def mod_pix(pix, data):
    datalist = gen_data(data)
    lendata = len(datalist)
    imdata = iter(pix)
    for i in range(lendata):
        pix = [value for value in imdata.__next__()[:3] +
               imdata.__next__()[:3] +
               imdata.__next__()[:3]]
        for j in range(0, 8):
            if (datalist[i][j] == '0') and (pix[j] % 2 != 0):
                pix[j] -= 1
            elif (datalist[i][j] == '1') and (pix[j] % 2 == 0):
                pix[j] -= 1
        if (i == lendata - 1):
            if (pix[-1] % 2 == 0):
                pix[-1] -= 1
        else:
            if (pix[-1] % 2 != 0):
                pix[-1] -= 1
        pix = tuple(pix)
        yield pix[0:3]
        yield pix[3:6]
        yield pix[6:9]

def encode_enc(newimg, data):
    w = newimg.size[0]
    (x, y) = (0, 0)
    for pixel in mod_pix(newimg.getdata(), data):
        newimg.putpixel((x, y), pixel)
        if (x == w - 1):
            x = 0
            y += 1
        else:
            x += 1

def encode_image(file_path, message):
    try:
        # Open and convert the image to PNG format for encoding
        myimg = Image.open(file_path).convert('RGBA')
        newimg = myimg.copy()
        encode_enc(newimg, message)
        
        # Save the encoded image with the original filename and extension
        original_extension = file_path.rsplit('.', 1)[1].lower()
        new_file_path = file_path 

        newimg.save(new_file_path, format='PNG')
        
        # Return the path to the saved encoded image
        return new_file_path
    except Exception as e:
        print(f"Error encoding image: {e}")
        return None

def decode_image(file_path):
    try:
        # Open and convert the encoded image to PNG format for decoding
        image = Image.open(file_path).convert('RGBA')
        data = ''
        imgdata = iter(image.getdata())
        while (True):
            pixels = [value for value in imgdata.__next__()[:3] +
                      imgdata.__next__()[:3] +
                      imgdata.__next__()[:3]]
            binstr = ''
            for i in pixels[:8]:
                if i % 2 == 0:
                    binstr += '0'
                else:
                    binstr += '1'
            data += chr(int(binstr, 2))
            if pixels[-1] % 2 != 0:
                return data
    except Exception as e:
        print(f"Error decoding image: {e}")
        return "Error decoding the image."

# Video Steganography
def extract_frames(video_path, output_dir):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    command = [
        'ffmpeg',
        '-i', video_path,
        os.path.join(output_dir, 'frame_%04d.png')
    ]
    try:
        subprocess.run(command, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error extracting frames: {e}")
        raise

def encode_text_in_frames(frames_dir, text):
    frame_files = sorted(os.listdir(frames_dir))
    for i, letter in enumerate(text):
        if i >= len(frame_files):
            break
        frame_file = frame_files[i]
        frame_path = os.path.join(frames_dir, frame_file)
        encoded_img = lsb.hide(frame_path, letter)
        encoded_img.save(frame_path)

def frames_to_video(frames_dir, output_video_path, frame_rate=30):
    command = [
        'ffmpeg',
        '-framerate', str(frame_rate),
        '-i', os.path.join(frames_dir, 'frame_%04d.png'),
        '-c:v', 'libx264',
        '-pix_fmt', 'yuv420p',
        output_video_path
    ]
    print(f"Running ffmpeg command: {' '.join(command)}")
    try:
        subprocess.run(command, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error converting frames to video: {e}")
        raise
def encode_video(input_video_path, message):
    mappings_folder = os.path.join(app.config['MAPPINGS_FOLDER'], os.path.basename(input_video_path))
    frames_folder = os.path.join(mappings_folder, 'frames')

    extract_frames(input_video_path, frames_folder)
    encode_text_in_frames(frames_folder, message)
    
    output_video_path = os.path.join(app.config['STATIC_FOLDER'], os.path.basename(input_video_path))
    frames_to_video(frames_folder, output_video_path)
    
    # Calculate the pass key
    pass_key = len(message) ^ 7777

    # Return the output video path and pass key
    return output_video_path, pass_key

def decode_video(input_video_path):
    mappings_folder = os.path.join(app.config['MAPPINGS_FOLDER'], os.path.basename(input_video_path))
    frames_folder = os.path.join(mappings_folder, 'frames')
    
    text_length = int(request.form['pass_key']) ^ 7777  # Retrieve the pass_key from the form
    decoded_message = decode_text_from_frames(frames_folder, text_length)
    try:
        shutil.rmtree(frames_folder)
        shutil.rmtree(mappings_folder)
    except Exception as e:
        print(f"Error during cleanup: {e}")
    
    return decoded_message if decoded_message else 'No message found.'

def decode_text_from_frames(frames_dir, text_length):
    frame_files = sorted(os.listdir(frames_dir))
    decoded_message = ""
    for i in range(text_length):
        frame_file = frame_files[i]
        frame_path = os.path.join(frames_dir, frame_file)
        decoded_letter = lsb.reveal(frame_path)
        if decoded_letter:
            decoded_message += decoded_letter
    return decoded_message


# Audio Steganography
def encode_audio(file_path, message):
    audio = AudioSegment.from_file(file_path)
    encoded_audio = encode_message_in_audio(audio, message)
    encoded_audio.export(file_path, format='wav')
    return file_path

def encode_message_in_audio(audio, message):
    raw_data = bytearray(audio.raw_data)
    message_binary = ''.join(format(ord(char), '08b') for char in message) + '00000000'

    if len(message_binary) > len(raw_data) * 8:
        raise ValueError("Message is too long for the provided audio file.")

    for i, bit in enumerate(message_binary):
        byte_index = i // 8
        bit_index = i % 8
        byte = raw_data[byte_index]
        raw_data[byte_index] = (byte & ~(1 << bit_index)) | (int(bit) << bit_index)

    encoded_audio = AudioSegment(
        raw_data,
        frame_rate=audio.frame_rate,
        sample_width=audio.sample_width,
        channels=audio.channels
    )

    return encoded_audio

def decode_message_from_audio(audio):
    raw_data = bytearray(audio.raw_data)
    extracted_bits = []

    for byte in raw_data:
        for bit_index in range(8):
            extracted_bits.append(str((byte >> bit_index) & 1))

    binary_message = ''.join(extracted_bits)
    
    decoded_message = ''
    for i in range(0, len(binary_message), 8):
        byte = binary_message[i:i+8]
        if len(byte) == 8:
            char = chr(int(byte, 2))
            if char == '\x00':
                break
            decoded_message += char

    return decoded_message

def decode_audio(file_path):
    audio = AudioSegment.from_file(file_path)
    return decode_message_from_audio(audio)

# Text Steganography
def encode_text(file_path, message):
    with open(file_path, 'w') as file:
        file.write(message)
    return file_path

def decode_text(file_path):
    with open(file_path, 'r') as file:
        return file.read() 

@app.errorhandler(405)
def method_not_allowed(e):
    print( "Method Not Allowed. Please use POST request.", 405)

if __name__ == '__main__':
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)
    app.run(debug=False)