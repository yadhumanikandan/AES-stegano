import tkinter as tk
from tkinter import ttk
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64
from tkinter import *
from tkinter import filedialog
from PIL import Image
import os
from stegano import lsb 



root=Tk()
root.title("steganography hide a secret text message in an image")
root.geometry("700x400")
root.resizable(False,False)
root.configure(bg="white")

style = ttk.Style()
style.configure('TButton', foreground='blue', font=('Helvetica', 12))
style.configure('TLabel', foreground='black', font=('Helvetica', 12))
style.configure('TEntry', font=('Helvetica', 12))


def generate_aes_key(key_length=20):
    return get_random_bytes(key_length)


def encrypt_message():
    try:
        message = message_entry.get().encode('utf-8')
        key = base64.b64decode(key_entry.get().encode('utf-8'))
        rounds = int(rounds_entry.get())

        cipher = AES.new(key, AES.MODE_ECB)

        for _ in range(rounds):
            message = cipher.encrypt(pad(message, AES.block_size))

        encrypted_message = base64.b64encode(message).decode('utf-8')
        message_entry.delete(0, tk.END)
        message_entry.insert(0, encrypted_message)
    except Exception as e:
        message_entry.delete(0, tk.END)
        message_entry.insert(0, "Error: " + str(e))


def decrypt_message():
    try:
        message = base64.b64decode(message_entry.get().encode('utf-8'))
        key = base64.b64decode(key_entry.get().encode('utf-8'))
        rounds = int(rounds_entry.get())

        cipher = AES.new(key, AES.MODE_ECB)

        for _ in range(rounds):
            message = unpad(cipher.decrypt(message), AES.block_size)

        decrypted_message = message.decode('utf-8')
        message_entry.delete(0, tk.END)
        message_entry.insert(0, decrypted_message)
    except Exception as e:
        message_entry.delete(0, tk.END)
        message_entry.insert(0, "Error: " + str(e))


def reset_entries():
    message_entry.delete(0, tk.END)
    aes_key = generate_aes_key()
    key_entry.delete(0, tk.END)
    key_entry.insert(0, base64.b64encode(aes_key).decode('utf-8'))
    rounds_entry.delete(0, tk.END)
    rounds_entry.insert(0, "1")  # Default to 1 round
    output_image_entry.delete(0, tk.END)


def save_to_file():
    global save_file_path
    save_file_path = "enc.txt"
    if save_file_path:
        with open(save_file_path, "w") as file:
            file.write(key_entry.get() + "\n")
            file.write(rounds_entry.get() + "\n")
            file.write(message_entry.get())

    hide_in_image()




def loadimage():
    filename=filedialog.askopenfilename(initialdir=os.getcwd(),title="select image file",
                                        filetypes=(("Image files", "*.png *.jpg *.jpeg"),
                                                    ("All files", "*.*")))
    return filename



def hide_in_image():
    img_path = loadimage()
    txt_path = save_file_path

    name = output_image_entry.get()

    image = Image.open(img_path)
    with open(txt_path, "r") as text_file:
        text = text_file.read()

    secret_image = lsb.hide(image, text)

    secret_image.save(name + ".png")


def extract_data():
    secret_image_path = loadimage()

    hidden_text = lsb.reveal(secret_image_path)

    lines = [line.strip() for line in hidden_text.splitlines()]

    message_entry.delete(0, tk.END)
    message_entry.insert(0, lines[2])
    key_entry.delete(0, tk.END)
    key_entry.insert(0, lines[0])
    rounds_entry.delete(0, tk.END)
    rounds_entry.insert(0, lines[1])



message_label = ttk.Label(root, text="Enter Message:")
message_entry = ttk.Entry(root, width=70)

aes_key = generate_aes_key()
key_label = ttk.Label(root, text="AES Key:")
key_entry = ttk.Entry(root, width=70)
key_entry.insert(0, base64.b64encode(aes_key).decode('utf-8'))

rounds_label = ttk.Label(root, text="Number of Rounds:")
rounds_entry = ttk.Entry(root)
rounds_entry.insert(0, "1")  # Default to 1 round

output_image_name = ttk.Label(root, text="Enter Output Image name:")
output_image_entry = ttk.Entry(root, width=70)

encrypt_button = ttk.Button(root, text="Encrypt", command=encrypt_message, width=20)
decrypt_button = ttk.Button(root, text="Decrypt", command=decrypt_message, width=20)

reset_button = ttk.Button(root, text="Reset", command=reset_entries, width=20)

hide_to_image = ttk.Button(root, text="Hide in Image", command=save_to_file, width=20)
extract_from_image = ttk.Button(root, text="extract from image", command=extract_data, width=20)




message_label.grid(row=0, column=0, padx=10, pady=5, sticky='w')
message_entry.grid(row=0, column=1, padx=10, pady=5, sticky='w')

key_label.grid(row=1, column=0, padx=10, pady=5, sticky='w')
key_entry.grid(row=1, column=1, padx=10, pady=5, sticky='w')

rounds_label.grid(row=2, column=0, padx=10, pady=5, sticky='w')
rounds_entry.grid(row=2, column=1, padx=10, pady=5, sticky='w')

output_image_name.grid(row=3, column=0, padx=10, pady=5, sticky='w')
output_image_entry.grid(row=3, column=1, padx=10, pady=5, sticky='w')

encrypt_button.grid(row=4, column=0, padx=10, pady=5, sticky='w')
hide_to_image.grid(row=4, column=1, padx=10, pady=5, sticky='w')

extract_from_image.grid(row=5, column=0, padx=10, pady=50, sticky='w')
decrypt_button.grid(row=5, column=1, padx=10, pady=5, sticky='w')

reset_button.grid(row=6, column=0, padx=10, pady=5, sticky='w')




root.mainloop()
