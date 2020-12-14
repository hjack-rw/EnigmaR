from flask import Flask
from flask_sqlalchemy import SQLAlchemy
import wave
import struct
import numpy
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = '29d3580a694df58df79edcd9ae33a530'
app.config['CLIENT_FILE'] = r'C:\Users\Rafal\PycharmProjects\enigmar\test13'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)


posts = [
    {
        'title': '1to0 (Atbash Cipher)',
        'url': '/cipher/1to0',
        'content': 'First post content'},

    {
        'title': 'Caesar Cipher',
        'url': '/cipher/caesar',
        'content': 'Second post content'},

    {
        'title': 'Vigenère Cipher',
        'url': '/cipher/vigenere',
        'content': 'Third post content'},

    {
        'title': 'New Cipher Disk',
        'url': '/cipher/newdisk',
        'content': 'Fourth post content'},

    {
        'title': 'Enigma',
        'url': '/enigma',
        'content': 'Fifth post content'}
]


def openSoundfile(file):
    wav_file = wave.open(file, 'r')
    channels, samples, fs, frames, comptype, compname = wav_file.getparams()
    data = wav_file.readframes(frames)
    wav_file.close()

    if channels == 1:
        ctype = 'h'
        data = struct.unpack('<{0}h'.format(frames), data)
    elif channels == 2:
        ctype = 'i'
        data = struct.unpack('<{0}i'.format(frames), data)

    data = numpy.array(data)
    return data, ctype, channels, samples, fs, frames, comptype, compname


def saveSoundfile(filename, decrypting, data, ctype, channels, samples, fs, frames, comptype, compname):
    if decrypting:
        filename = filename.replace('_enc', '')
        filename = f'{filename[:-4]}_dec.wav'
    else:
        filename = f'{filename[:-4]}_enc.wav'

    wav_file = wave.open(os.path.join(app.config['CLIENT_FILE'], filename), 'w')
    wav_file.setparams((channels, samples, fs, frames, comptype, compname))

    if ctype == 'h':
        data = struct.pack('<{0}h'.format(frames), *data)
    elif ctype == 'i':
        data = struct.pack('<{0}i'.format(frames), *data)

    wav_file.writeframesraw(data)
    wav_file.close()
    return filename


import main.routes