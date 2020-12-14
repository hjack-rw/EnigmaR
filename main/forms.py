from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, SubmitField, SelectField, BooleanField
from wtforms.validators import DataRequired, ValidationError
from main import db

rotors = {1: 'I', 2: 'II', 3: 'III', 4: 'IV', 5: 'V', 6: 'VI', 7: 'VII', 8: 'VIII'}
ciphers = ['1to0', 'CAESAR', 'VIGENERE', 'NEW DISK']
ciphers2 = ['CAESAR', 'VIGENERE', 'NEW DISK', 'ENIGMA']
alphabet = list("ABCDEFGHIJKLMNOPQRSTUVWXYZ.,!?:'")


class CipherForm(FlaskForm):
    def newDiskCheck(self, form):
        cipher, new_disk = self.cipher.data.upper(), self.new_disk.data
        if cipher == 'NEW DISK' and (all(new_disk.count(character) != 1 for character in alphabet) or len(self.new_disk.data) != len(alphabet)):
            raise ValidationError("The disk must contain all letters from the alphabet ( and . , ! ? : ' ) once without any space in between")
        else:
            pass

    def indexCheck(self, form):
        cipher, index, decrypting, index_encrypting = self.cipher.data.upper(), self.index.data, self.decrypting.data, self.index_encrypting.data
        if cipher == '1TO0' and index:
            raise ValidationError("1to0 doesn't require an index")
        elif cipher != '1TO0' and not index and not decrypting:
            cipher_name = cipher.capitalize()
            cipher_name = cipher_name.replace('New disk', 'New Disk')
            raise ValidationError(f"{cipher_name} cipher requires an index")
        elif cipher == 'CAESAR' and (len(index) > 1 and not index_encrypting):
            raise ValidationError(f"Caesar cipher requires an index of length one")
        elif (not all(character in alphabet for character in index.upper()) and not index_encrypting) or index is None:
            raise ValidationError(f"Only letters and . , ! ? : ' are allowed as an index")

    def indexEncryptingCheck(self, form):
        cipher, index, decrypting, index_encrypting = self.cipher.data.upper(), self.index.data.upper(), self.decrypting.data, self.index_encrypting.data
        if decrypting:
            command, notcommand = "INDEXONLY_", "GENERATE_"
        else:
            command, notcommand = "GENERATE_", "INDEXONLY_"

        if index_encrypting:
            if index.startswith("ALL-") and not decrypting:
                raise ValidationError(f"Only letters and . , ! ? : ' are allowed as an index")
            elif index.startswith(command):
                index = index.split("_")[1]

        if index_encrypting:
            if cipher == "1TO0":
                raise ValidationError(f"1to0 doesn't have an index to encrypt")
            elif index.startswith(notcommand):
                raise ValidationError(f"That's not a valid command")
            elif index.isdigit():
                if int(index) <= 0:
                    raise ValidationError(f"Index length must be greater than 0")
                elif cipher == "CAESAR" and int(index) > 1:
                    raise ValidationError(f"That's not possible")
            elif cipher == "CAESAR" and index.startswith("ALL-"):
                raise ValidationError(f"That's not possible")
            elif index.startswith("ALL-"):
                index = index.replace("ALL-", "")
                if not index.isdigit():
                    raise ValidationError("After the command an integer is expected")
                elif int(index) <= 0:
                    raise ValidationError(f"Index length must be greater or equal 0")
            elif not all(character in alphabet for character in index.upper()) and not decrypting:
                raise ValidationError(f"Only letters and . , ! ? : ' are allowed as an index")
            elif decrypting and not index == 'ALL':
                raise ValidationError(f"Decrypting with an encrypted index requires an integer input greater than 0")

    cipher = SelectField('Cipher', choices=[(cipher.lower(), cipher) for cipher in ciphers])
    index = StringField('Index', validators=[indexCheck])
    decrypting = BooleanField('Decrypt?')
    new_disk = StringField(' ', validators=[newDiskCheck])
    index_encrypting = BooleanField('Index Encryption?', validators=[indexEncryptingCheck])

    soundfile = FileField('Load Sound File', validators=[FileAllowed(['wav']), DataRequired()])
    submit = SubmitField('Ok')


class WithFileForm(FlaskForm):
    cipher = SelectField('Cipher', choices=[(cipher.lower(), cipher) for cipher in ciphers2])
    decrypting = BooleanField('Decrypt?')

    soundfile = FileField('Load Sound File', validators=[FileAllowed(['wav']), DataRequired()])
    cipher_soundfile = FileField('Load the Encrypting Sound File', validators=[FileAllowed(['wav']), DataRequired()])
    submit = SubmitField('Ok')


class ROTOR(db.Model):
    __tablename__ = 'rotor0'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(1))


class POSITION(db.Model):
    __tablename__ = 'position0'

    id = db.Column(db.Integer, primary_key=True)
    character = db.Column(db.String(1))
    rotor_id = db.Column(db.Integer)


class REFLECTOR(db.Model):
    __tablename__ = 'reflector'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(1, 5))
    rotor_id = db.Column(db.Integer)


class EnigmaForm(FlaskForm):
    def plugboardCheck(self, form):
        plugboard = self.plugboard.data.upper()
        if not plugboard:
            pass
        elif not (plugboard.startswith('[') or plugboard.endswith(']')):
            raise ValidationError("Please, write within a squeare bracket")
        elif not (len(plugboard) - 1) % 3 == 0:
            raise ValidationError(
                "Please, write two different characters each time with a space between them e.g. [AB] or [AB CD]")
        else:
            x = 0
            duplicates = []
            for instance in range(len(plugboard)):
                if plugboard[instance] == '[' or plugboard[instance] == ']':
                    continue
                elif instance == 3 + x:
                    if not plugboard[instance] == ' ':
                        raise ValidationError("There has to be a space between the characters")
                    else:
                        x += 3
                        continue
                elif instance != 3:
                    if not plugboard[instance] in alphabet:
                        raise ValidationError("Only letter and . , ! ? : ' combinations are allowed")
                    else:
                        duplicates.append(plugboard[instance].upper())
                        continue
            check = list(set(duplicates))
            if not len(check) == len(duplicates):
                raise ValidationError("The letters need to be different")

    rotor0 = SelectField('Rotors', choices=[(rotor.id, rotor.name) for rotor in ROTOR.query.all()], validate_choice=False)
    rotor1 = SelectField(choices=[(rotor, rotors[rotor]) for rotor in rotors], validate_choice=False)
    rotor2 = SelectField(choices=[(rotor, rotors[rotor]) for rotor in rotors], validate_choice=False)
    rotor3 = SelectField(choices=[(rotor, rotors[rotor]) for rotor in rotors], validate_choice=False)

    position0 = SelectField('Position', choices=[], validate_choice=False)
    position1 = SelectField(choices=[(character, character) for character in alphabet], validate_choice=False)
    position2 = SelectField(choices=[(character, character) for character in alphabet], validate_choice=False)
    position3 = SelectField(choices=[(character, character) for character in alphabet], validate_choice=False)

    ring0 = SelectField('Rings', choices=[], validate_choice=False)
    ring1 = SelectField(choices=[(character, character) for character in alphabet], validate_choice=False)
    ring2 = SelectField(choices=[(character, character) for character in alphabet], validate_choice=False)
    ring3 = SelectField(choices=[(character, character) for character in alphabet], validate_choice=False)

    reflector = SelectField('Reflector', choices=[], validate_choice=False)
    plugboard = StringField('Plugboard', validators=[plugboardCheck])

    soundfile = FileField('Load Sound File', validators=[FileAllowed(['wav']), DataRequired()])
    submit = SubmitField('Ok')
