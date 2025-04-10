import tkinter as tk
from tkinter import ttk
from tkinter import scrolledtext
from tkinter import messagebox
import string
import re # For cleaning keywords
import math # For ceiling function (grid calculation)

# --- Constants ---
PADDING_CHAR = 'X' # Character used for padding in transposition

# --- Core Cipher Logic ---

def get_key_order(key):
    """
    Determines the column read/write order for transposition based on the keyword.
    Handles duplicate letters by their order of appearance.
    Example: key="SECRET" -> S=3, E=1, C=0, R=2, E=4, T=5 -> Order=[2, 1, 4, 3, 0, 5] (C, E1, E2, R, S, T)
             Actual read order: [C, E, R, E, S, T] -> indices [2, 1, 3, 4, 0, 5] - Wait, standard is alphabetical.
    Let's use standard alphabetical order.
    Example: key="SECRET" -> C E E R S T -> indices [2, 1, 4, 3, 0, 5]
    Returns a list of column indices in the order they should be processed.
    """
    key = key.lower() # Case-insensitive order
    # Create pairs of (letter, original_index)
    indexed_key = list(enumerate(key))
    # Sort based on the letter, then original index for stability (though not strictly needed for std alphabet order)
    sorted_indexed_key = sorted(indexed_key, key=lambda item: item[1])
    # Extract the original indices in the new sorted order
    order = [index for index, char in sorted_indexed_key]
    return order

def transposition_encrypt(text, key):
    """Encrypts using keyed columnar transposition."""
    key = re.sub(r'[^a-zA-Z]', '', key) # Clean key
    if not key:
        raise ValueError("Transposition keyword must contain at least one letter.")

    key_order = get_key_order(key)
    num_cols = len(key)
    num_rows = math.ceil(len(text) / num_cols)
    padding_len = (num_rows * num_cols) - len(text)
    padded_text = text + PADDING_CHAR * padding_len

    ciphertext = ""
    # Read column by column based on key order
    for col_index in key_order:
        for row in range(num_rows):
            ciphertext += padded_text[row * num_cols + col_index]
    return ciphertext

def transposition_decrypt(ciphertext, key):
    """Decrypts using keyed columnar transposition."""
    key = re.sub(r'[^a-zA-Z]', '', key) # Clean key
    if not key:
        raise ValueError("Transposition keyword must contain at least one letter.")

    key_order = get_key_order(key)
    num_cols = len(key)
    num_rows = math.ceil(len(ciphertext) / num_cols)
    num_shaded_cells = (num_rows * num_cols) - len(ciphertext) # Cells *not* filled in the last row

    # Create a grid (list of columns)
    plaintext_cols = [''] * num_cols
    ciphertext_index = 0

    # Determine which original columns correspond to the sorted order
    original_col_positions = [0] * num_cols
    for i, k_idx in enumerate(key_order):
        original_col_positions[k_idx] = i

    # Fill the grid column by column according to key order
    for col_index in key_order:
        # Calculate rows for this column (handle potentially shorter last row)
        rows_in_this_col = num_rows
        # If this column index is among the last 'num_shaded_cells' columns *in the original grid layout*
        # and the current column's index in the *sorted key* is >= (num_cols - num_shaded_cells) ? No simpler way:
        original_index_this_col_comes_from = col_index # The actual column index 0..N-1
        is_short_column = (original_index_this_col_comes_from >= num_cols - num_shaded_cells)

        if is_short_column:
             rows_in_this_col -= 1


        # Read the characters for this column from the ciphertext
        col_chars = ciphertext[ciphertext_index : ciphertext_index + rows_in_this_col]
        plaintext_cols[col_index] = col_chars # Store chars under their original column index
        ciphertext_index += rows_in_this_col

    # Read the grid row by row to reconstruct plaintext
    plaintext = ""
    for row in range(num_rows):
        for col in range(num_cols):
             # Check if the current column has a character at this row index
             if row < len(plaintext_cols[col]):
                 plaintext += plaintext_cols[col][row]

    # Remove padding (this might remove genuine 'X's at the end)
    # A more robust system would store the original length or use unambiguous padding
    # For this example, we assume padding was only added Xs at the very end.
    # Count how many padding chars were theoretically added
    original_padding_len = (num_rows * num_cols) - len(ciphertext) + num_shaded_cells # this calc seems wrong
    # Let's re-calc original padding length
    original_padding_len = (num_rows * num_cols) - len(ciphertext) # This is padding chars *added*

    # A simpler, though potentially flawed, approach for trailing padding:
    if plaintext.endswith(PADDING_CHAR * original_padding_len):
         plaintext = plaintext[:-original_padding_len]
    else:
         # Fallback: remove all trailing padding chars, maybe too aggressive
         plaintext = plaintext.rstrip(PADDING_CHAR)


    return plaintext


def process_text(text, key, mode, cipher_type):
    """
    Encrypts or decrypts text using the selected cipher.
    """
    result = ""
    # Clean the text input slightly (optional, but can help avoid issues)
    # text = text.strip() # Already handled in handlers

    if cipher_type == 'caesar':
        if not isinstance(key, int):
            raise ValueError("Caesar key (shift) must be an integer.")
        shift = key if mode == 'encrypt' else -key

        for char in text:
            if char.isalpha():
                start = ord('a') if char.islower() else ord('A')
                shifted_pos = (ord(char) - start + shift) % 26
                result += chr(start + shifted_pos)
            else:
                result += char # Keep non-alphabetic characters

    elif cipher_type == 'vigenere':
        if not isinstance(key, str) or not key:
            raise ValueError("Vigenere key (keyword) must be a non-empty string.")
        keyword = re.sub(r'[^a-zA-Z]', '', key).lower()
        if not keyword:
             raise ValueError("Vigenere keyword must contain at least one letter.")

        key_index = 0
        for char in text:
            if char.isalpha():
                key_char = keyword[key_index % len(keyword)]
                key_shift = ord(key_char) - ord('a')
                if mode == 'decrypt':
                    key_shift = -key_shift

                start = ord('a') if char.islower() else ord('A')
                shifted_pos = (ord(char) - start + key_shift) % 26
                result += chr(start + shifted_pos)
                key_index += 1
            else:
                result += char

    elif cipher_type == 'transposition':
         if not isinstance(key, str) or not key:
            raise ValueError("Transposition key (keyword) must be a non-empty string.")
         # Key cleaning happens inside the specific functions
         if mode == 'encrypt':
             result = transposition_encrypt(text, key)
         elif mode == 'decrypt':
             result = transposition_decrypt(text, key)
         else:
             raise ValueError(f"Unknown mode for transposition: {mode}")

    else:
        raise ValueError(f"Unknown cipher type: {cipher_type}")

    return result

# --- GUI Event Handlers ---

def update_key_input_visibility(*args):
    """Shows/hides key input fields based on selected cipher."""
    selected_cipher = cipher_var.get()
    if selected_cipher == "caesar":
        caesar_key_frame.pack(pady=5, padx=10, fill="x")
        keyword_frame.pack_forget() # Hide Keyword input
        keyword_label.config(text="Keyword:") # Reset label just in case
    elif selected_cipher == "vigenere":
        caesar_key_frame.pack_forget() # Hide Caesar input
        keyword_label.config(text="Vigenère Keyword:") # Specific label
        keyword_frame.pack(pady=5, padx=10, fill="x")
    elif selected_cipher == "transposition":
        caesar_key_frame.pack_forget() # Hide Caesar input
        keyword_label.config(text="Transposition Key:") # Specific label
        keyword_frame.pack(pady=5, padx=10, fill="x")
    else:
        caesar_key_frame.pack_forget()
        keyword_frame.pack_forget()

def handle_process(mode):
    """Handles both encryption and decryption based on selected cipher."""
    input_val = input_text_area.get("1.0", tk.END).strip()
    selected_cipher = cipher_var.get()
    key = None
    error_title = "Encryption Error" if mode == 'encrypt' else "Decryption Error"

    # --- Input Validation ---
    if not input_val:
        messagebox.showerror("Input Error", f"Please enter text to {mode}.")
        return

    try:
        if selected_cipher == 'caesar':
            shift_str = shift_entry.get().strip()
            if not shift_str:
                messagebox.showerror("Input Error", "Please enter a Caesar shift key (integer).")
                return
            try:
                key = int(shift_str)
            except ValueError:
                messagebox.showerror("Input Error", "Caesar shift key must be a whole number (integer).")
                return
        elif selected_cipher in ['vigenere', 'transposition']:
            keyword_str = keyword_entry.get().strip()
            if not keyword_str:
                cipher_name = "Vigenère" if selected_cipher == 'vigenere' else "Transposition"
                messagebox.showerror("Input Error", f"Please enter a {cipher_name} keyword.")
                return
            # Further validation (e.g., must contain letters after cleaning) happens inside process_text
            key = keyword_str
        else:
             messagebox.showerror("Internal Error", "No valid cipher selected.")
             return
    except Exception as e: # Catch potential issues during key retrieval/validation
        messagebox.showerror("Input Error", f"Error getting key: {e}")
        return
    # --- End Validation ---

    # --- Process Text ---
    try:
        processed_text = process_text(input_val, key, mode, selected_cipher)
        output_text_area.configure(state='normal') # Enable writing
        output_text_area.delete("1.0", tk.END)     # Clear previous output
        output_text_area.insert(tk.END, processed_text) # Insert new output
        output_text_area.configure(state='disabled') # Disable editing
    except ValueError as ve: # Catch specific validation errors from process_text
        messagebox.showerror(error_title, f"Input Error: {ve}")
    except Exception as e: # Catch other potential processing errors
        messagebox.showerror(error_title, f"An error occurred during processing: {e}\n(Cipher: {selected_cipher}, Mode: {mode})")
        # Optional: Add more details for debugging
        # import traceback
        # messagebox.showerror(error_title, f"An error occurred: {e}\n{traceback.format_exc()}")


# --- GUI Setup ---
root = tk.Tk()
root.title("Cipher Tool (Caesar, Vigenère, Transposition)")
root.geometry("550x580") # Slightly taller for the extra radio button

# Style
style = ttk.Style()
style.theme_use('clam')

# --- Input Area ---
input_frame = ttk.LabelFrame(root, text="Input Text (Plaintext or Ciphertext)")
input_frame.pack(pady=10, padx=10, fill="x")

input_text_area = scrolledtext.ScrolledText(input_frame, wrap=tk.WORD, width=60, height=8, font=("Arial", 10))
input_text_area.pack(pady=5, padx=5, fill="both", expand=True)

# --- Cipher Selection ---
cipher_frame = ttk.LabelFrame(root, text="Select Cipher")
cipher_frame.pack(pady=5, padx=10, fill="x")

cipher_var = tk.StringVar(value="caesar") # Default
cipher_var.trace_add("write", update_key_input_visibility)

caesar_radio = ttk.Radiobutton(cipher_frame, text="Caesar", variable=cipher_var, value="caesar")
caesar_radio.pack(side=tk.LEFT, padx=(10, 5), pady=5)

vigenere_radio = ttk.Radiobutton(cipher_frame, text="Vigenère", variable=cipher_var, value="vigenere")
vigenere_radio.pack(side=tk.LEFT, padx=5, pady=5)

transposition_radio = ttk.Radiobutton(cipher_frame, text="Transposition", variable=cipher_var, value="transposition")
transposition_radio.pack(side=tk.LEFT, padx=5, pady=5)


# --- Key Input Frames (Container) ---
key_input_container = ttk.Frame(root)
key_input_container.pack(pady=0, padx=0, fill="x")

# Caesar Key Input Frame
caesar_key_frame = ttk.Frame(key_input_container)
shift_label = ttk.Label(caesar_key_frame, text="Shift Key (Integer):")
shift_label.pack(side=tk.LEFT, padx=(10, 5))
shift_entry = ttk.Entry(caesar_key_frame, width=10)
shift_entry.pack(side=tk.LEFT)

# Keyword Input Frame (Used by Vigenere and Transposition)
keyword_frame = ttk.Frame(key_input_container)
# Label text will be updated by update_key_input_visibility
keyword_label = ttk.Label(keyword_frame, text="Keyword:") # Generic initial text
keyword_label.pack(side=tk.LEFT, padx=(10, 5))
keyword_entry = ttk.Entry(keyword_frame, width=20)
keyword_entry.pack(side=tk.LEFT)


# --- Buttons ---
button_frame = ttk.Frame(root)
button_frame.pack(pady=10)

encrypt_button = ttk.Button(button_frame, text="Encrypt", command=lambda: handle_process('encrypt'))
encrypt_button.pack(side=tk.LEFT, padx=10)

decrypt_button = ttk.Button(button_frame, text="Decrypt", command=lambda: handle_process('decrypt'))
decrypt_button.pack(side=tk.LEFT, padx=10)

# --- Output Area ---
output_frame = ttk.LabelFrame(root, text="Output Result")
output_frame.pack(pady=10, padx=10, fill="x")

output_text_area = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, width=60, height=8, font=("Arial", 10), state='disabled')
output_text_area.pack(pady=5, padx=5, fill="both", expand=True)

# --- Initial GUI State ---
update_key_input_visibility()

# --- Run the GUI ---
root.mainloop()