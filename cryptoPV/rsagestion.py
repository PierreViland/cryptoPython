# rsagestion.py

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
import base64
import os


class RsaGestion:
    def __init__(self):
        print("Construction de la classe")

        self.clefPrive = None
        self.clefPublic = None
    def __del__(self):
        print("Destructeur par défaut du RSA")

    def generation_clef(self, nom_fichier_public, nom_fichier_prive, taille):
        key = RSA.generate(taille)
        self.clefPrive = key
        self.clefPublic = key.publickey()

        with open(nom_fichier_prive, 'wb') as f:
            f.write(key.export_key('PEM'))
        print(f"Ecriture clef privée dans {nom_fichier_prive}")

        with open(nom_fichier_public, 'wb') as f:
            f.write(self.clefPublic.export_key('PEM'))
        print(f"Ecriture clef publique dans {nom_fichier_public}")

    def chargement_clefs(self, fichier_public, fichier_prive):
        self.chargement_clef_privee(fichier_prive)
        self.chargement_clef_publique(fichier_public)

    def chargement_clef_privee(self, fichier_prive):
        with open(fichier_prive, 'rb') as f:
            self.clefPrive = RSA.import_key(f.read())

    def chargement_clef_publique(self, fichier_public):
        with open(fichier_public, 'rb') as f:
            self.clefPublic = RSA.import_key(f.read())

    def chiffrement_rsa(self, donne_claire):
        cipher = PKCS1_OAEP.new(self.clefPublic)
        donne_claire_bytes = donne_claire.encode('utf-8')
        donne_chiffree = cipher.encrypt(donne_claire_bytes)
        return base64.b64encode(donne_chiffree).decode('utf-8')

    def dechiffrement_rsa(self, message_chiffre):
        cipher = PKCS1_OAEP.new(self.clefPrive)
        donne_chiffree = base64.b64decode(message_chiffre)
        donne_claire = cipher.decrypt(donne_chiffree)
        return donne_claire.decode('utf-8')

    def chiffre_dans_fichier(self, donnee, nom_fichier):
        donne_chiffree = self.chiffrement_rsa(donnee)
        with open(nom_fichier, 'w', encoding='utf-8') as f:
            f.write(donne_chiffree)
        print("Fichier enregistré avec succès.")

    def dechiffre_fichier(self, nom_fichier):
        try:
            with open(nom_fichier, 'r', encoding='utf-8') as f:
                message_chiffre = f.read()
            return self.dechiffrement_rsa(message_chiffre)
        except Exception as e:
            print("Erreur :", e)
            return ""

    def chiffrement_fichier(self, fichier_entree, fichier_sortie, format64=True):
        if format64:
            with open(fichier_entree, 'r', encoding='utf-8') as f:
                texte = f.read()
            self.chiffre_dans_fichier(texte, fichier_sortie)
        else:
            cipher = PKCS1_OAEP.new(self.clefPublic)
            with open(fichier_entree, 'rb') as f_in:
                data = f_in.read()
                encrypted = cipher.encrypt(data)
            with open(fichier_sortie, 'wb') as f_out:
                f_out.write(encrypted)

    def dechiffrement_fichier(self, fichier_entree, fichier_sortie, format64=True):
        if format64:
            texte = self.dechiffre_fichier(fichier_entree)
            with open(fichier_sortie, 'w', encoding='utf-8') as f:
                f.write(texte)
        else:
            cipher = PKCS1_OAEP.new(self.clefPrive)
            with open(fichier_entree, 'rb') as f_in:
                encrypted = f_in.read()
                decrypted = cipher.decrypt(encrypted)
            with open(fichier_sortie, 'wb') as f_out:
                f_out.write(decrypted)
