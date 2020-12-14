from flask import render_template, current_app, flash, jsonify, send_from_directory, after_this_request
from main import app, posts, openSoundfile, saveSoundfile
from main.forms import CipherForm, WithFileForm, EnigmaForm, ROTOR, POSITION, REFLECTOR
from main.test11 import CIPHER, ENIGMA, readLSB, generateIndex, cipherWithFile
from datetime import datetime
import os


@app.route('/')
@app.route('/home')
def home():
    return render_template('home.html', posts=posts)


@app.route('/about')
def about():
    return render_template('about.html', title='About')


@app.route('/cipher/<cipher>', methods=['GET', 'POST'])
def cipher(cipher):
    form = CipherForm()

    if cipher == "newdisk":
        cipher = "new disk"
        cipher_name = "New Disk"
    else:
        cipher_name = cipher.capitalize()

    form.cipher.data = cipher

    if form.validate_on_submit():
        now = datetime.now()
        beginning_time = now.strftime('%H:%M:%S')

        file = form.soundfile.data
        data, ctype, channels, samples, fs, frames, comptype, compname = openSoundfile(file)

        if cipher == "new disk":
            cipher = form.new_disk.data.upper()
        else:
            cipher = form.cipher.data.upper()

        decrypting = form.decrypting.data
        index_encrypting = form.index_encrypting.data
        index_string = form.index.data.upper()

        try:
            command = index_string.split("_")[0]
            index_string = index_string.split("_")[1]
            if cipher == "CAESAR" and index_string == "ALL":
                index_string = "1"
        except IndexError:
            if cipher == "1TO0":
                index_encrypting, index, index_string = None, None, None

        if command == "INDEXONLY":
            _, index_string = readLSB(data, ctype, index_string, False)
            flash(f'Your secret message: {index_string}', 'info')
        else:
            if command == "GENERATE":
                index_string = generateIndex(data, ctype, index_string)
            elif decrypting and index_encrypting:
                _, index_string = readLSB(data, ctype, index_string, False)

            for data_index, data_instance in enumerate(data):
                try:
                    data[data_index], index, index_encrypting = CIPHER(data_instance, ctype, cipher, decrypting, index_encrypting, [index, data_index], index_string).resultCipher()
                except NameError:
                    data[data_index], index, index_encrypting = CIPHER(data_instance, ctype, cipher, decrypting, index_encrypting, [-1, data_index], index_string).resultCipher()

            filename = saveSoundfile(f'{file.filename}', decrypting, data, ctype, channels, samples, fs, frames, comptype, compname)
            url = "<a href=\"" + f'/download/{filename}' + "\">Download</a>"

            now = datetime.now()
            end_time = now.strftime('%H:%M:%S')
            flash(f"Your file has been encrypted! Start: {beginning_time} End: {end_time} {url}", 'info')
    return render_template('cipher.html', title=f'{cipher_name} Cipher', form=form)


@app.route('/cipher/withfile/<cipher>', methods=['GET', 'POST'])
def withFile(cipher):
    form = WithFileForm()

    if cipher == "newdisk":
        cipher = "new disk"
        cipher_name = "New Disk"
    else:
        cipher_name = cipher.capitalize()

    form.cipher.data = cipher

    if form.validate_on_submit():
        now = datetime.now()
        beginning_time = now.strftime('%H:%M:%S')

        file = form.soundfile.data
        data, ctype, channels, samples, fs, frames, comptype, compname = openSoundfile(file)

        file2 = form.cipher_soundfile.data
        data2, ctype2, _, _, _, _, _, _ = openSoundfile(file2)

        cipher = form.cipher.data.upper()
        decrypting = form.decrypting.data
        index_encrypting = False

        if cipher == "ENIGMA":
            rotors, turnover, reflector, position, rings, plugboard = cipherWithFile(data2, ctype2, cipher)
            decrypting = False
        elif cipher == "NEW DISK":
            index_string, cipher = cipherWithFile(data2, ctype2, cipher)
        else:
            index_string, _ = cipherWithFile(data2, ctype2, cipher)

        del data2, ctype2

        for data_index, data_instance in enumerate(data):
            if cipher == "ENIGMA":
                data[data_index], _, _, _, _, _, _ = ENIGMA(data_instance, ctype, rotors, turnover, reflector, position, rings, plugboard).resultEnigma()
            else:
                try:
                    data[data_index], index, index_encrypting = CIPHER(data_instance, ctype, cipher, decrypting, index_encrypting, [index, data_index], index_string).resultCipher()
                except NameError:
                    data[data_index], index, index_encrypting = CIPHER(data_instance, ctype, cipher, decrypting, index_encrypting, [-1, data_index], index_string).resultCipher()

        filename = saveSoundfile(f'{file.filename}', decrypting, data, ctype, channels, samples, fs, frames, comptype, compname)
        url = "<a href=\"" + f'/download/{filename}' + "\">Download</a>"

        now = datetime.now()
        end_time = now.strftime('%H:%M:%S')
        flash(f"Your file has been encrypted! Start: {beginning_time} End: {end_time} {url}", 'info')
    return render_template('withfile.html', title=f'{cipher_name} Cipher', form=form)


@app.route('/position/<get_position>')
def positionByRotor(get_position):
    position = POSITION.query.filter_by(rotor_id=get_position).all()
    position_array = []
    for instance in position:
        object = {}
        object['character'] = instance.character
        object['position'] = instance.character
        position_array.append(object)
    return jsonify({'rotor_position': position_array})


@app.route('/reflector/<get_reflector>')
def reflectorByRotor(get_reflector):
    reflector = REFLECTOR.query.filter_by(rotor_id=get_reflector).all()
    reflector_array = []
    for instance in reflector:
        object = {}
        if instance.id > 5:
            object['id'] = instance.id - 3
        else:
            object['id'] = instance.id - 1

        object['name'] = instance.name
        reflector_array.append(object)
    return jsonify({'rotor_reflector': reflector_array})


@app.route('/enigma', methods=['GET', 'POST'])
def enigma():
    form = EnigmaForm()

    if form.validate_on_submit():
        now = datetime.now()
        beginning_time = now.strftime('%H:%M:%S')

        file = form.soundfile.data
        data, ctype, channels, samples, fs, frames, comptype, compname = openSoundfile(file)

        use_instead = ['', '0', '9']
        rotors = f'{use_instead[int(form.rotor0.data) - 1]}{form.rotor1.data}{form.rotor2.data}{form.rotor3.data}'
        turnover = []
        reflector = int(form.reflector.data)
        position = f'{form.position0.data}{form.position1.data}{form.position2.data}{form.position3.data}'.replace('-','')
        rings = f'{form.ring0.data}{form.ring1.data}{form.ring2.data}{form.ring3.data}'.replace('-', '')
        plugboard = form.plugboard.data.upper()[1: -1]

        for data_index, data_instance in enumerate(data):
            data[data_index], rotors, turnover, reflector, position, rings, plugboard = ENIGMA(data_instance, ctype, rotors, turnover, reflector, position, rings, plugboard).resultEnigma()

        filename = saveSoundfile(f'{file.filename}', False, data, ctype, channels, samples, fs, frames, comptype, compname)
        url = "<a href=\"" + f'/download/{filename}' + "\">Download</a>"

        now = datetime.now()
        end_time = now.strftime('%H:%M:%S')
        flash(f"Your file has been encrypted! Start: {beginning_time} End: {end_time} {url}", 'info')
    return render_template('enigma.html', title='Enigma', form=form)


@app.route('/download/<filename>')
def download_file(filename):
    path = os.path.join(app.config['CLIENT_FILE'], filename)

    #@after_this_request
    #def remove_file(response):
    def generate():
        with open(path) as file:
            yield from file
        os.remove(path)
        #return response

    #return send_from_directory(app.config['CLIENT_FILE'], filename, as_attachment=True)
    response = current_app.response_class(generate(), mimetype='audio/wav')
    response.headers.set('Content-Disposition', 'attachment', filename=filename)
    return response