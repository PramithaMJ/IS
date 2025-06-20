import tkinter as tk
from tkinter import messagebox
import random

# 5-bit encoding for full a-z alphabet
letter_to_bits = {
    'a': '00000', 'b': '00001', 'c': '00010', 'd': '00011', 'e': '00100',
    'f': '00101', 'g': '00110', 'h': '00111', 'i': '01000', 'j': '01001',
    'k': '01010', 'l': '01011', 'm': '01100', 'n': '01101', 'o': '01110',
    'p': '01111', 'q': '10000', 'r': '10001', 's': '10010', 't': '10011',
    'u': '10100', 'v': '10101', 'w': '10110', 'x': '10111', 'y': '11000',
    'z': '11001'
}
bits_to_letter = {v: k for k, v in letter_to_bits.items()}

def text_to_bits(text):
    # Convert to lowercase and only keep a-z characters
    text = ''.join(c.lower() for c in text if c.lower() in letter_to_bits)
    return ''.join(letter_to_bits[c] for c in text)

def bits_to_text(bits):
    # Now using 5 bits per letter
    return ''.join(bits_to_letter.get(bits[i:i+5], '?') for i in range(0, len(bits), 5))

def xor_bits(a, b):
    return ''.join(str(int(x)^int(y)) for x, y in zip(a, b))

def random_key(length):
    return ''.join(random.choice('01') for _ in range(length))

# GUI Application
class OTPSimulator:
    def __init__(self, root):
        self.root = root
        root.title("One-Time Pad Simulator")

        tk.Label(root, text="Plaintext (a-z):").grid(row=0, column=0)
        self.plain_entry = tk.Entry(root, width=40)
        self.plain_entry.grid(row=0, column=1)

        tk.Button(root, text="Generate Random Key", command=self.generate_key).grid(row=1, column=0)
        self.key_entry = tk.Entry(root, width=40)
        self.key_entry.grid(row=1, column=1)

        tk.Button(root, text="Encrypt", command=self.encrypt).grid(row=2, column=0)
        self.cipher_label = tk.Label(root, text="Ciphertext:")
        self.cipher_label.grid(row=2, column=1)
        
        tk.Button(root, text="Decrypt with Real Key", command=self.decrypt).grid(row=3, column=0)
        self.decrypt_label = tk.Label(root, text="Decrypted Text:")
        self.decrypt_label.grid(row=3, column=1)

        tk.Label(root, text="Fake Key to Forge Decryption:").grid(row=4, column=0)
        self.fake_key_entry = tk.Entry(root, width=40)
        self.fake_key_entry.grid(row=4, column=1)

        tk.Label(root, text="Desired Forged Message (a-z):").grid(row=5, column=0)
        self.desired_forge_entry = tk.Entry(root, width=40)
        self.desired_forge_entry.grid(row=5, column=1)
        
        tk.Button(root, text="Calculate Fake Key", command=self.calculate_fake_key).grid(row=6, column=0)
        tk.Button(root, text="Decrypt with Fake Key", command=self.fake_decrypt).grid(row=7, column=0)
        self.fake_plain_label = tk.Label(root, text="Forged Plaintext:")
        self.fake_plain_label.grid(row=7, column=1)

    def generate_key(self):
        text = self.plain_entry.get()
        bits = text_to_bits(text)
        key = random_key(len(bits))
        self.key_entry.delete(0, tk.END)
        self.key_entry.insert(0, key)

    def encrypt(self):
        text = self.plain_entry.get()
        bits = text_to_bits(text)
        key = self.key_entry.get()

        if len(key) != len(bits):
            messagebox.showerror("Error", "Key must be same length as bit string.")
            return

        ciphertext = xor_bits(bits, key)
        letters = bits_to_text(ciphertext)
        self.cipher_label.config(text=f"Ciphertext: {ciphertext}  ({letters})")

    def decrypt(self):
        cipher_text = self.cipher_label.cget("text").split(":")[1].split()[0]
        key = self.key_entry.get()

        if not cipher_text:
            messagebox.showerror("Error", "No ciphertext to decrypt. Encrypt a message first.")
            return
            
        if len(cipher_text) != len(key):
            messagebox.showerror("Error", "Key length must match ciphertext length.")
            return

        decrypted_bits = xor_bits(cipher_text, key)
        decrypted_text = bits_to_text(decrypted_bits)
        self.decrypt_label.config(text=f"Decrypted Text: {decrypted_text}")
            
    def calculate_fake_key(self):
        cipher_text = self.cipher_label.cget("text").split(":")[1].split()[0]
        desired_text = self.desired_forge_entry.get()
        
        if not cipher_text:
            messagebox.showerror("Error", "No ciphertext available. Encrypt a message first.")
            return
            
        # Convert desired text to bits
        desired_bits = text_to_bits(desired_text)
        
        # Ensure desired message fits the ciphertext length
        if len(desired_bits) > len(cipher_text):
            messagebox.showerror("Error", "Desired message is too long for the ciphertext.")
            return
        
        # If shorter, pad with 'a's (00000)
        while len(desired_bits) < len(cipher_text):
            desired_bits += letter_to_bits['a']
            
        # Calculate the fake key that would produce the desired text
        fake_key = xor_bits(cipher_text, desired_bits)
        
        # Set the fake key
        self.fake_key_entry.delete(0, tk.END)
        self.fake_key_entry.insert(0, fake_key)
        
        messagebox.showinfo("Fake Key Generated", 
                            "A fake key has been calculated that will forge the ciphertext into your desired message.")
    
    def fake_decrypt(self):
        cipher_text = self.cipher_label.cget("text").split(":")[1].split()[0]
        fake_key = self.fake_key_entry.get()

        if not cipher_text:
            messagebox.showerror("Error", "No ciphertext to decrypt. Encrypt a message first.")
            return
            
        if len(cipher_text) != len(fake_key):
            messagebox.showerror("Error", "Fake key length must match ciphertext length.")
            return

        forged_plain_bits = xor_bits(cipher_text, fake_key)
        forged_text = bits_to_text(forged_plain_bits)
        self.fake_plain_label.config(text=f"Forged Plaintext: {forged_text}")

# Run GUI
root = tk.Tk()
app = OTPSimulator(root)
root.mainloop()
