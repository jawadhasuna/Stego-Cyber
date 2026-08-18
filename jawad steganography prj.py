# ==============================================================================
#                           IMPORTS AND LIBRARIES
# ==============================================================================
import tkinter as tk #makes gui
from tkinter import filedialog, messagebox, ttk # Tkinter for GUI
from PIL import Image, ImageTk # Pillow for image manipulation or processing
import os # For OS-level operations like path handling and random number generation
import base64 # For encoding binary data to ASCII strings
import hashlib # For creating hash digests (e.g., for deriving encryption keys)
from Crypto.Cipher import AES # PyCryptodome for AES encryption
from Crypto.Util.Padding import pad, unpad # Utilities for padding/unpadding for AES
# Note: Ensure PyCryptodome is installed: pip install pycryptodomex

# ==============================================================================
#                               CONSTANTS
# ==============================================================================
DELIMITER = '1111111111111110'  # 16-bit binary delimiter (0xFFFE). Marks the end of hidden data in the image.
AES_KEY_SIZE = 16  # Specifies a 128-bit key for AES encryption (16 bytes * 8 bits/byte = 128 bits).
AES_IV_SIZE = 16   # AES block size and Initialization Vector (IV) size is 16 bytes (128 bits).

# ==============================================================================
#                 CORE CRYPTOGRAPHY AND STEGANOGRAPHY FUNCTIONS
# ==============================================================================

# ------------------------------------------------------------------------------
# Function: encrypt_message_data
# Purpose: Encrypts a plaintext message using AES-256 in CBC mode.
# Arguments:
#   message_str (str): The plaintext message to be encrypted.
#   password_str (str): The password used to derive the encryption key.
# Returns:
#   str: A Base64 encoded string containing the IV prepended to the ciphertext.
#        Returns None if an error occurs during encryption.
# ------------------------------------------------------------------------------
def encrypt_message_data(message_str, password_str):
    """
    Encrypts the message string using AES-256 CBC mode.
    The password is used to derive a secure encryption key.
    The IV is randomly generated and prepended to the ciphertext.
    The final output (IV + ciphertext) is Base64 encoded for safe handling as a string.
    """
    try:
        # 1. Derive Encryption Key:
        #    Use MD5 to hash the password. The digest is used as the AES key.
        #    This ensures the key is of the correct length (16 bytes for AES-128)
        #    and is deterministically derived from the password.
        key = hashlib.md5(password_str.encode('utf-8')).digest()
        
        # 2. Generate Initialization Vector (IV):
        #    A random IV is crucial for CBC mode security. It ensures that encrypting
        #    the same plaintext multiple times with the same key results in different ciphertexts.
        iv = os.urandom(AES_IV_SIZE) # Generates 16 random bytes
        
        # 3. Create AES Cipher Object:
        #    Initialize the AES cipher in Cipher Block Chaining (CBC) mode.
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        # 4. Pad and Encrypt Message:
        #    AES works on fixed-size blocks. The message must be padded to a multiple
        #    of the AES block size (16 bytes) before encryption.
        #    The message is first encoded to UTF-8 bytes.
        padded_message = pad(message_str.encode('utf-8'), AES.block_size)
        encrypted_message_bytes = cipher.encrypt(padded_message)
        
        # 5. Combine IV and Ciphertext:
        #    The IV must be stored alongside the ciphertext as it's needed for decryption.
        #    It's common practice to prepend the IV to the ciphertext.
        encrypted_payload = iv + encrypted_message_bytes
        
        # 6. Base64 Encode:
        #    Encode the combined (IV + ciphertext) byte string into a Base64 string.
        #    Base64 makes binary data safe to transmit or store as text (e.g., to hide in an image).
        return base64.b64encode(encrypted_payload).decode('utf-8')
        
    except Exception as e:
        # Catch any unexpected errors during the encryption process.
        messagebox.showerror("Encryption Error", f"Failed to encrypt message: {str(e)}")
        return None

# ------------------------------------------------------------------------------
# Function: decrypt_message_data
# Purpose: Decrypts a Base64 encoded ciphertext using AES-256 in CBC mode.
# Arguments:
#   base64_encrypted_data_str (str): The Base64 encoded string (IV + ciphertext).
#   password_str (str): The password used to derive the decryption key.
# Returns:
#   str: The decrypted plaintext message.
#        Returns None if decryption fails (e.g., wrong password, corrupted data).
# ------------------------------------------------------------------------------
def decrypt_message_data(base64_encrypted_data_str, password_str):
    """
    Decrypts the Base64 encoded encrypted data using AES-128 CBC mode.
    The password is used to re-derive the same encryption key.
    The IV is extracted from the beginning of the decoded data.
    """
    try:
        # 1. Derive Decryption Key:
        #    Must be identical to the key derivation in encryption.
        key = hashlib.md5(password_str.encode('utf-8')).digest()
        
        # 2. Base64 Decode:
        #    Convert the Base64 string back into its original byte form (IV + ciphertext).
        encrypted_payload_bytes = base64.b64decode(base64_encrypted_data_str)
        
        # 3. Extract IV and Ciphertext:
        #    The first AES_IV_SIZE (16) bytes are the IV.
        iv = encrypted_payload_bytes[:AES_IV_SIZE]
        #    The remaining bytes are the actual encrypted message.
        encrypted_message_bytes = encrypted_payload_bytes[AES_IV_SIZE:]
        
        # 4. Create AES Cipher Object:
        #    Initialize the AES cipher with the derived key and extracted IV.
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        # 5. Decrypt and Unpad Message:
        #    Decrypt the ciphertext.
        decrypted_padded_message_bytes = cipher.decrypt(encrypted_message_bytes)
        #    Remove the padding added during encryption to retrieve the original message bytes.
        decrypted_message_bytes = unpad(decrypted_padded_message_bytes, AES.block_size)
        
        # 6. Decode to String:
        #    Convert the decrypted bytes back into a UTF-8 string.
        return decrypted_message_bytes.decode('utf-8')
        
    except (ValueError, KeyError) as e:
        # These errors often occur if the password is wrong (leading to incorrect key)
        # or if the data is corrupted, causing padding errors during unpad.
        messagebox.showerror("Decryption Error", "Decryption failed. Incorrect password or corrupted data.")
        return None
    except Exception as e:
        # Catch any other unexpected errors during decryption.
        messagebox.showerror("Decryption Error", f"An unexpected error occurred during decryption: {str(e)}")
        return None

# ------------------------------------------------------------------------------
# Function: hide_data_in_image
# Purpose: Hides a string (data_to_hide_str) within the pixels of an image
#          using the Least Significant Bit (LSB) steganography technique.
# Arguments:
#   image_path_str (str): Path to the cover image file.
#   data_to_hide_str (str): The string data to hide (typically Base64 encoded encrypted message).
#   app_context (dict): Application context (not directly used here but passed for consistency).
# Returns:
#   str: Path to the newly created image with hidden data if successful.
#        Returns None if the process fails.
# ------------------------------------------------------------------------------
def hide_data_in_image(image_path_str, data_to_hide_str, app_context):
    """
    Hides data within an image using LSB steganography.
    The data_to_hide_str is converted to its binary representation, a delimiter is appended,
    and then each bit is embedded into the LSB of the color channels (R, G, B) of the image pixels.
    """
    try:
        # 1. Open and Prepare Image:
        img = Image.open(image_path_str)
        img = img.convert('RGB') # Ensure image is in RGB format for consistent LSB manipulation.

        # 2. Prepare Data for Hiding:
        #    Convert each character of the data_to_hide_str (e.g., Base64 string) into its 8-bit binary form.
        #    Example: 'A' (ASCII 65) -> '01000001'
        binary_data_to_hide = ''.join(format(ord(char), '08b') for char in data_to_hide_str)
        #    Append the DELIMITER to the binary string. This marker is used during extraction
        #    to know where the hidden data ends.
        binary_data_to_hide += DELIMITER

        # 3. Check Image Capacity:
        pixels = list(img.getdata()) # Get a flat list of all pixel tuples (R,G,B)
        # Each pixel can store 3 bits (1 in R's LSB, 1 in G's LSB, 1 in B's LSB).
        if len(binary_data_to_hide) > len(pixels) * 3:
            messagebox.showerror("Error", "Image too small for the message. Please choose a larger image or a shorter message.")
            return None

        # 4. Embed Data into Pixels:
        data_idx = 0 # Index for iterating through binary_data_to_hide
        new_pixels = [] # List to store modified pixel data

        for r_orig, g_orig, b_orig in pixels:
            r, g, b = r_orig, g_orig, b_orig # Work with copies of original pixel values

            # Embed in Red channel's LSB if data remains
            if data_idx < len(binary_data_to_hide):
                # (r & ~1) clears the LSB (sets to 0).
                # | int(binary_data_to_hide[data_idx]) sets LSB to the current data bit.
                r = (r & ~1) | int(binary_data_to_hide[data_idx])
                data_idx += 1
            
            # Embed in Green channel's LSB if data remains
            if data_idx < len(binary_data_to_hide):
                g = (g & ~1) | int(binary_data_to_hide[data_idx])
                data_idx += 1
            
            # Embed in Blue channel's LSB if data remains
            if data_idx < len(binary_data_to_hide):
                b = (b & ~1) | int(binary_data_to_hide[data_idx])
                data_idx += 1
            
            new_pixels.append((r, g, b)) # Add modified (or original if no data embedded) pixel

            # If all data has been embedded, stop modifying pixels
            if data_idx >= len(binary_data_to_hide):
                # Optimization: Append the rest of the original pixels without modification
                new_pixels.extend(pixels[len(new_pixels):])
                break
        
        # 5. Create and Save New Image:
        new_img = Image.new(img.mode, img.size) # Create a new image with the same mode and size
        new_img.putdata(new_pixels) # Populate it with the modified pixel data

        # Ask user where to save the steganographic image
        output_path = filedialog.asksaveasfilename(
            title="Save Encoded Image As",
            defaultextension=".png", # PNG is lossless and good for steganography
            filetypes=[("PNG files", "*.png"), ("All files", "*.*")]
        )
        if output_path:
            new_img.save(output_path, "PNG") # Save in PNG format to preserve LSB changes
            return output_path
        return None # User cancelled save dialog

    except FileNotFoundError:
        messagebox.showerror("File Error", f"Image file not found: {image_path_str}")
        return None
    except Exception as e:
        messagebox.showerror("Image Hiding Error", f"Failed to hide data in image: {str(e)}")
        return None

# ------------------------------------------------------------------------------
# Function: extract_data_from_image
# Purpose: Extracts hidden data from an image that was encoded using LSB steganography.
# Arguments:
#   image_path_str (str): Path to the steganographic image.
#   app_context (dict): Application context (not directly used here).
# Returns:
#   str: The extracted string data (expected to be a Base64 encoded string).
#        Returns None if extraction fails or no data is found.
# ------------------------------------------------------------------------------
def extract_data_from_image(image_path_str, app_context):
    """
    Extracts hidden data from an image using LSB steganography.
    It reads the LSB of each color channel of each pixel, reconstructs the binary string,
    stops when the delimiter is found, and then converts the binary string back to characters.
    """
    try:
        # 1. Open and Prepare Image:
        img = Image.open(image_path_str)
        img = img.convert('RGB') # Ensure image is in RGB format

        pixels = list(img.getdata()) # Get pixel data
        extracted_binary_data = "" # To store the extracted bits
        delimiter_len = len(DELIMITER)

        # 2. Extract Bits from LSBs:
        for r, g, b in pixels:
            # Extract LSB from Red channel
            extracted_binary_data += str(r & 1)
            # Check if delimiter is found
            if len(extracted_binary_data) >= delimiter_len and extracted_binary_data.endswith(DELIMITER):
                extracted_binary_data = extracted_binary_data[:-delimiter_len] # Remove delimiter
                break 
            
            # Extract LSB from Green channel
            extracted_binary_data += str(g & 1)
            if len(extracted_binary_data) >= delimiter_len and extracted_binary_data.endswith(DELIMITER):
                extracted_binary_data = extracted_binary_data[:-delimiter_len]
                break
            
            # Extract LSB from Blue channel
            extracted_binary_data += str(b & 1)
            if len(extracted_binary_data) >= delimiter_len and extracted_binary_data.endswith(DELIMITER):
                extracted_binary_data = extracted_binary_data[:-delimiter_len]
                break
        else: 
            # This 'else' belongs to the 'for' loop. It executes if the loop completed naturally
            # (i.e., without a 'break' statement, meaning delimiter was not found).
            messagebox.showwarning("Extraction Warning", "End-of-data delimiter not found. Data might be corrupted, incomplete, or not present.")
            return None

        # 3. Validate Extracted Data:
        if not extracted_binary_data:
             messagebox.showwarning("Extraction Warning", "No data found before delimiter. The image might not contain a message.")
             return None

        # The length of the binary data must be a multiple of 8 to form valid bytes.
        if len(extracted_binary_data) % 8 != 0:
            messagebox.showerror("Extraction Error", "Corrupted data: Incomplete byte sequence extracted. The binary data length is not a multiple of 8.")
            return None
            
        # 4. Convert Binary String to Characters:
        byte_values = [] # To store integer values of each byte
        for i in range(0, len(extracted_binary_data), 8):
            byte_segment = extracted_binary_data[i:i+8] # Get an 8-bit segment
            byte_values.append(int(byte_segment, 2)) # Convert binary segment to integer
        
        # Convert the list of byte integers into a byte string, then decode to a UTF-8 string.
        # This reconstructed string should be the original Base64 encoded data.
        # 'errors="ignore"' can be risky but helps if minor non-UTF-8 chars appear;
        # for Base64, 'ascii' or 'utf-8' without 'ignore' should generally work.
        reconstructed_base64_string = bytes(byte_values).decode('utf-8', errors='ignore') 
        return reconstructed_base64_string

    except FileNotFoundError:
        messagebox.showerror("File Error", f"Encoded image file not found: {image_path_str}")
        return None
    except Exception as e:
        messagebox.showerror("Image Extraction Error", f"Failed to extract data from image: {str(e)}")
        return None

# ==============================================================================
#                           GUI HELPER FUNCTIONS
# ==============================================================================

# ------------------------------------------------------------------------------
# Function: display_image_preview
# Purpose: Loads an image and displays it as a thumbnail in a Tkinter Label widget.
# Arguments:
#   image_path_str (str): Path to the image file.
#   preview_label_widget (tk.Label): The Tkinter Label widget to display the preview.
# ------------------------------------------------------------------------------
def display_image_preview(image_path_str, preview_label_widget):
    """Displays an image preview in the given Tkinter Label widget."""
    try:
        img = Image.open(image_path_str)
        # Create a thumbnail for preview. LANCZOS is a high-quality downsampling filter.
        img.thumbnail((300, 200), Image.Resampling.LANCZOS) 
        
        photo_img = ImageTk.PhotoImage(img) # Convert PIL Image to Tkinter PhotoImage
        preview_label_widget.config(image=photo_img, text="") # Update label with image
        preview_label_widget.image = photo_img # IMPORTANT: Keep a reference to prevent garbage collection
    except FileNotFoundError:
        preview_label_widget.config(text=f"Preview Error: File not found\n{image_path_str}", image=None)
        preview_label_widget.image = None
    except Exception as e:
        preview_label_widget.config(text=f"Error loading preview: {str(e)}", image=None)
        preview_label_widget.image = None


# ==============================================================================
#                           GUI ACTION CALLBACKS
# ==============================================================================
# These functions are called when GUI elements (like buttons) are interacted with.

# ------------------------------------------------------------------------------
# Function: browse_image_action
# Purpose: Opens a file dialog for the user to select an image.
#          Updates the application context and image preview.
# Arguments:
#   app_context (dict): The application's shared state and widget references.
#   encode_tab (bool): True if browsing for encoding, False for decoding.
# ------------------------------------------------------------------------------
def browse_image_action(app_context, encode_tab=True):
    """Handles browsing for an image for encoding or decoding."""
    try:
        path = filedialog.askopenfilename(
            title="Select Image File",
            filetypes=[("Image files", "*.png;*.jpg;*.jpeg;*.bmp;*.gif"), ("All files", "*.*")]
        )
        if path: # If a file was selected (path is not empty)
            if encode_tab:
                app_context["image_path_encode"] = path
                display_image_preview(path, app_context["widgets"]["preview_label_encode"])
                app_context["widgets"]["status_var"].set(f"Image for encoding: {os.path.basename(path)}")
            else: # For decode tab
                app_context["image_path_decode"] = path
                display_image_preview(path, app_context["widgets"]["preview_label_decode"])
                app_context["widgets"]["status_var"].set(f"Image for decoding: {os.path.basename(path)}")
    except Exception as e:
        messagebox.showerror("Browse Error", f"An error occurred while browsing for image: {str(e)}")
        if encode_tab:
            app_context["widgets"]["status_var"].set("Error selecting image for encoding.")
        else:
            app_context["widgets"]["status_var"].set("Error selecting image for decoding.")


# ------------------------------------------------------------------------------
# Function: encode_message_action
# Purpose: Orchestrates the message encoding process:
#          1. Gathers inputs (image, message, password).
#          2. Encrypts the message.
#          3. Hides the encrypted data in the image.
#          4. Provides feedback to the user.
# Arguments:
#   app_context (dict): The application's shared state and widget references.
# ------------------------------------------------------------------------------
def encode_message_action(app_context):
    """Handles the 'Encode Message' button click event."""
    try:
        # 1. Get Inputs from GUI
        image_path = app_context.get("image_path_encode", "")
        message = app_context["widgets"]["message_text_encode"].get("1.0", tk.END).strip()
        password = app_context["widgets"]["password_entry_encode"].get()
        confirm_password = app_context["widgets"]["confirm_password_entry_encode"].get()

        # 2. Validate Inputs
        if not image_path:
            messagebox.showerror("Input Error", "Please select an image first.")
            return
        if not message:
            messagebox.showerror("Input Error", "Please enter a secret message to hide.")
            return
        if not password:
            messagebox.showerror("Input Error", "Please enter a password for encryption.")
            return
        if password != confirm_password:
            messagebox.showerror("Input Error", "Passwords do not match. Please re-enter.")
            return

        # 3. Update Status and Process
        app_context["widgets"]["status_var"].set("Processing: Encrypting and encoding message...")
        app_context["root"].update_idletasks() # Force GUI update

        encrypted_b64_data = encrypt_message_data(message, password)
        if encrypted_b64_data:
            output_stego_path = hide_data_in_image(image_path, encrypted_b64_data, app_context)
            if output_stego_path:
                messagebox.showinfo("Success", f"Message encoded and hidden successfully!\nSaved to: {output_stego_path}")
                app_context["widgets"]["status_var"].set(f"Encoded and saved: {os.path.basename(output_stego_path)}")
            else:
                # Error message already shown by hide_data_in_image or user cancelled save
                app_context["widgets"]["status_var"].set("Encoding failed or was cancelled.")
        else:
            # Error message already shown by encrypt_message_data
            app_context["widgets"]["status_var"].set("Encryption of message failed.")
    
    except Exception as e:
        messagebox.showerror("Encoding Error", f"An unexpected error occurred during encoding: {str(e)}")
        app_context["widgets"]["status_var"].set("An unexpected encoding error occurred.")
    finally:
        # Clear password fields after attempt, regardless of success or failure
        if "widgets" in app_context and "password_entry_encode" in app_context["widgets"]:
            app_context["widgets"]["password_entry_encode"].delete(0, tk.END)
        if "widgets" in app_context and "confirm_password_entry_encode" in app_context["widgets"]:
            app_context["widgets"]["confirm_password_entry_encode"].delete(0, tk.END)


# ------------------------------------------------------------------------------
# Function: decode_message_action
# Purpose: Orchestrates the message decoding process:
#          1. Gathers inputs (encoded image, password).
#          2. Extracts hidden (Base64) data from the image.
#          3. Decrypts the extracted data.
#          4. Displays the original message or an error.
# Arguments:
#   app_context (dict): The application's shared state and widget references.
# ------------------------------------------------------------------------------
def decode_message_action(app_context):
    """Handles the 'Decode Message' button click event."""
    decoded_text_widget = app_context["widgets"]["decoded_message_text"]
    try:
        # 1. Get Inputs from GUI
        image_path = app_context.get("image_path_decode", "")
        password = app_context["widgets"]["decode_password_entry"].get()

        # 2. Validate Inputs
        if not image_path:
            messagebox.showerror("Input Error", "Please select an encoded image first.")
            return
        if not password:
            messagebox.showerror("Input Error", "Please enter the password for decryption.")
            return

        # 3. Update Status and Prepare Output Area
        app_context["widgets"]["status_var"].set("Processing: Extracting and decrypting message...")
        app_context["root"].update_idletasks() # Force GUI update
        
        decoded_text_widget.config(state="normal") # Enable text area for output
        decoded_text_widget.delete("1.0", tk.END)  # Clear previous content

        # 4. Process: Extract and Decrypt
        extracted_b64_data = extract_data_from_image(image_path, app_context)
        if extracted_b64_data:
            decrypted_message = decrypt_message_data(extracted_b64_data, password)
            if decrypted_message is not None: # Check for None (failure) vs empty string (valid)
                decoded_text_widget.insert("1.0", decrypted_message)
                messagebox.showinfo("Success", "Message decoded successfully!")
                app_context["widgets"]["status_var"].set("Decoding successful.")
            else:
                # Error already shown by decrypt_message_data (e.g., wrong password)
                decoded_text_widget.insert("1.0", "Decryption failed. Please check the password or data integrity.")
                app_context["widgets"]["status_var"].set("Decryption failed.")
        else:
            # Error already shown by extract_data_from_image (e.g., no data, delimiter not found)
            decoded_text_widget.insert("1.0", "Failed to extract data from the image. It might not contain a message or could be corrupted.")
            app_context["widgets"]["status_var"].set("Extraction from image failed.")
            
    except Exception as e:
        messagebox.showerror("Decoding Error", f"An unexpected error occurred during decoding: {str(e)}")
        decoded_text_widget.insert("1.0", f"An unexpected error occurred: {str(e)}")
        app_context["widgets"]["status_var"].set("An unexpected decoding error occurred.")
    finally:
        # Disable text area and clear password field
        if decoded_text_widget:
            decoded_text_widget.config(state="disabled")
        if "widgets" in app_context and "decode_password_entry" in app_context["widgets"]:
            app_context["widgets"]["decode_password_entry"].delete(0, tk.END)


# ==============================================================================
#                           GUI SETUP FUNCTIONS
# ==============================================================================
# These functions build the various parts of the Tkinter user interface.

# ------------------------------------------------------------------------------
# Function: setup_encode_tab
# Purpose: Creates and configures all widgets for the 'Encode Message' tab.
# Arguments:
#   parent_notebook (ttk.Notebook): The notebook widget to which this tab will be added.
#   app_context (dict): The application's shared state and widget references.
# ------------------------------------------------------------------------------
def setup_encode_tab(parent_notebook, app_context):
    """Sets up the 'Encode Message' tab with all its UI elements."""
    encode_frame = tk.Frame(parent_notebook, bg="#f5f5f5") # Main frame for this tab
    parent_notebook.add(encode_frame, text="Encode Message") # Add tab to notebook

    # --- Layout: Split tab into left (input) and right (image) sections ---
    left_frame = tk.Frame(encode_frame, bg="#f5f5f5")
    left_frame.pack(side=tk.LEFT, fill="both", expand=True, padx=10, pady=10)
    
    right_frame = tk.Frame(encode_frame, bg="#f5f5f5")
    right_frame.pack(side=tk.RIGHT, fill="both", expand=True, padx=10, pady=10)

    # --- Input Data Section (Left Panel) ---
    input_frame = tk.LabelFrame(left_frame, text="Input Data", bg="#f5f5f5", font=("Helvetica", 12, "bold"), padx=10, pady=10)
    input_frame.pack(fill="both", expand=True, padx=5, pady=5)

    tk.Label(input_frame, text="Secret Message:", bg="#f5f5f5", font=("Helvetica", 10)).pack(anchor="w", padx=5, pady=(10,0))
    # Store message text widget in app_context for later access
    app_context["widgets"]["message_text_encode"] = tk.Text(input_frame, height=10, width=40, font=("Helvetica", 10), relief=tk.SOLID, borderwidth=1, wrap=tk.WORD)
    app_context["widgets"]["message_text_encode"].pack(fill="both", expand=True, padx=5, pady=5)

    tk.Label(input_frame, text="Password for Encryption:", bg="#f5f5f5", font=("Helvetica", 10)).pack(anchor="w", padx=5, pady=(10,0))
    app_context["widgets"]["password_entry_encode"] = tk.Entry(input_frame, show="•", width=30, relief=tk.SOLID, borderwidth=1, font=("Helvetica", 10))
    app_context["widgets"]["password_entry_encode"].pack(fill="x", padx=5, pady=5)

    tk.Label(input_frame, text="Confirm Password:", bg="#f5f5f5", font=("Helvetica", 10)).pack(anchor="w", padx=5, pady=(10,0))
    app_context["widgets"]["confirm_password_entry_encode"] = tk.Entry(input_frame, show="•", width=30, relief=tk.SOLID, borderwidth=1, font=("Helvetica", 10))
    app_context["widgets"]["confirm_password_entry_encode"].pack(fill="x", padx=5, pady=5)

    # --- Image Selection Section (Right Panel) ---
    image_frame = tk.LabelFrame(right_frame, text="Cover Image Selection", bg="#f5f5f5", font=("Helvetica", 12, "bold"), padx=10, pady=10)
    image_frame.pack(fill="both", expand=True, padx=5, pady=5)

    # Label to display image preview
    app_context["widgets"]["preview_label_encode"] = tk.Label(image_frame, text="No image selected", bg="#e0e0e0", width=40, height=15, relief=tk.GROOVE, borderwidth=2)
    app_context["widgets"]["preview_label_encode"].pack(fill="both", expand=True, padx=5, pady=5)
    
    # Frame to hold Browse and Encode buttons
    buttons_frame = tk.Frame(image_frame, bg="#f5f5f5")
    buttons_frame.pack(fill="x", padx=5, pady=(15,5)) # Add more padding on top

    browse_btn = tk.Button(buttons_frame, text="Browse Image", 
                           command=lambda: browse_image_action(app_context, encode_tab=True), 
                           bg="#4CAF50", fg="white", font=("Helvetica", 10, "bold"), relief=tk.RAISED, borderwidth=2, width=15, padx=5, pady=5)
    browse_btn.pack(side=tk.LEFT, padx=(0,10), expand=True)

    encode_btn = tk.Button(buttons_frame, text="Encode Message", 
                           command=lambda: encode_message_action(app_context), 
                           bg="#2196F3", fg="white", font=("Helvetica", 10, "bold"), relief=tk.RAISED, borderwidth=2, width=15, padx=5, pady=5)
    encode_btn.pack(side=tk.RIGHT, padx=(10,0), expand=True)


# ------------------------------------------------------------------------------
# Function: setup_decode_tab
# Purpose: Creates and configures all widgets for the 'Decode Message' tab.
# Arguments:
#   parent_notebook (ttk.Notebook): The notebook widget to which this tab will be added.
#   app_context (dict): The application's shared state and widget references.
# ------------------------------------------------------------------------------
def setup_decode_tab(parent_notebook, app_context):
    """Sets up the 'Decode Message' tab with all its UI elements."""
    decode_frame = tk.Frame(parent_notebook, bg="#f5f5f5") # Main frame for this tab
    parent_notebook.add(decode_frame, text="Decode Message") # Add tab to notebook

    # --- Layout: Split tab into left (image) and right (output) sections ---
    left_frame = tk.Frame(decode_frame, bg="#f5f5f5")
    left_frame.pack(side=tk.LEFT, fill="both", expand=True, padx=10, pady=10)
    
    right_frame = tk.Frame(decode_frame, bg="#f5f5f5")
    right_frame.pack(side=tk.RIGHT, fill="both", expand=True, padx=10, pady=10)

    # --- Encoded Image Section (Left Panel) ---
    image_frame = tk.LabelFrame(left_frame, text="Encoded Image Selection", bg="#f5f5f5", font=("Helvetica", 12, "bold"), padx=10, pady=10)
    image_frame.pack(fill="both", expand=True, padx=5, pady=5)

    # Label to display image preview
    app_context["widgets"]["preview_label_decode"] = tk.Label(image_frame, text="No image selected", bg="#e0e0e0", width=40, height=15, relief=tk.GROOVE, borderwidth=2)
    app_context["widgets"]["preview_label_decode"].pack(fill="both", expand=True, padx=5, pady=5)

    decode_browse_btn = tk.Button(image_frame, text="Browse Encoded Image", 
                                  command=lambda: browse_image_action(app_context, encode_tab=False), 
                                  bg="#4CAF50", fg="white", font=("Helvetica", 10, "bold"), relief=tk.RAISED, borderwidth=2, width=20, padx=5, pady=5)
    decode_browse_btn.pack(pady=10, fill=tk.X, padx=5)

    # --- Decode Output Section (Right Panel) ---
    output_frame = tk.LabelFrame(right_frame, text="Decryption and Output", bg="#f5f5f5", font=("Helvetica", 12, "bold"), padx=10, pady=10)
    output_frame.pack(fill="both", expand=True, padx=5, pady=5)

    tk.Label(output_frame, text="Password for Decryption:", bg="#f5f5f5", font=("Helvetica", 10)).pack(anchor="w", padx=5, pady=(10,0))
    app_context["widgets"]["decode_password_entry"] = tk.Entry(output_frame, show="•", width=30, relief=tk.SOLID, borderwidth=1, font=("Helvetica", 10))
    app_context["widgets"]["decode_password_entry"].pack(fill="x", padx=5, pady=5)

    decode_btn = tk.Button(output_frame, text="Decode Message", 
                           command=lambda: decode_message_action(app_context), 
                           bg="#2196F3", fg="white", font=("Helvetica", 10, "bold"), relief=tk.RAISED, borderwidth=2, width=15, padx=5, pady=5)
    decode_btn.pack(pady=10)

    tk.Label(output_frame, text="Decoded Message:", bg="#f5f5f5", font=("Helvetica", 10)).pack(anchor="w", padx=5, pady=(10,0))
    # Text area for displaying decoded message (initially disabled)
    app_context["widgets"]["decoded_message_text"] = tk.Text(output_frame, height=8, width=40, font=("Helvetica", 10), state="disabled", relief=tk.SOLID, borderwidth=1, wrap=tk.WORD)
    app_context["widgets"]["decoded_message_text"].pack(fill="both", expand=True, padx=5, pady=5)


# ------------------------------------------------------------------------------
# Function: create_main_window
# Purpose: Creates the main application window, initializes the overall layout,
#          and sets up the tabbed interface.
# Returns:
#   tuple: (tk.Tk, dict) - The root Tkinter window and the application context.
# ------------------------------------------------------------------------------
def create_main_window():
    """Creates the main application window and initializes the GUI."""
    root = tk.Tk()
    root.title("Jawad's Secure Steganography System")
    root.geometry("950x650") # Slightly increased size for better spacing
    # root.resizable(False, False) # Consider allowing resizing for accessibility
    root.configure(bg="#f5f5f5") # Light grey background for the root window

    # --- Application Icon (Optional) ---
    # Tries to set an application icon. Create a 'lock.ico' file in the same directory.
    icon_path = "lock.ico" 
    if os.path.exists(icon_path):
        try:
            root.iconbitmap(icon_path)
        except tk.TclError:
            # This can happen if the .ico file is invalid or on some OS configurations.
            print(f"Warning: Could not load icon '{icon_path}'. Make sure it's a valid .ico file or compatible with your OS.")
            
    # --- Application Context ---
    # A dictionary to store shared application state (like image paths)
    # and references to important widgets, making them accessible across functions.
    app_context = {
        "root": root, # Reference to the main window
        "image_path_encode": "", # Path to the image selected for encoding
        "image_path_decode": "", # Path to the image selected for decoding
        "widgets": {} # Dictionary to store references to various GUI widgets
    }

    # --- Main Content Frame ---
    # A central frame to hold the title and notebook, providing consistent padding.
    main_frame = tk.Frame(root, bg="#f5f5f5")
    main_frame.pack(fill="both", expand=True, padx=20, pady=20)

    # --- Application Title Label ---
    title_label = tk.Label(main_frame, text="Jawad's Secure Steganography System", 
                           font=("Helvetica", 20, "bold"), bg="#f5f5f5", fg="#333333") # Dark grey text
    title_label.pack(pady=(0, 25)) # Padding below the title

    # --- Tabbed Interface (Notebook) ---
    notebook = ttk.Notebook(main_frame)
    
    # --- Styling for Notebook Tabs ---
    # Uses ttk.Style to customize the appearance of the notebook tabs.
    style = ttk.Style()
    # Configure the font and padding for individual tabs
    style.configure("TNotebook.Tab", font=("Helvetica", 11, "bold"), padding=[15, 8], foreground="#333333")
    # Configure the overall notebook (e.g., tab position)
    style.configure("TNotebook", tabposition='n') # 'n' for North (tabs on top)
    # Optional: Add a light border around the tab content area
    style.configure("TNotebook.Tab", relief=tk.RAISED, borderwidth=1)
    style.map("TNotebook.Tab",
              background=[("selected", "#e0e0e0"), ("active", "#ececec")], # Lighter grey for selected/active
              foreground=[("selected", "#000000")])


    notebook.pack(fill="both", expand=True, pady=(0,10)) # Padding below notebook

    # --- Setup Individual Tabs ---
    # Call functions to create the content for each tab.
    # The app_context is passed so these functions can store widget references.
    setup_encode_tab(notebook, app_context)
    setup_decode_tab(notebook, app_context)

    # --- Status Bar ---
    # A bar at the bottom of the window to display status messages.
    app_context["widgets"]["status_var"] = tk.StringVar(value="Ready. Select an operation.")
    status_bar = tk.Label(root, textvariable=app_context["widgets"]["status_var"], 
                          bd=1, relief=tk.SUNKEN, anchor=tk.W, padx=10, pady=3, font=("Helvetica", 9))
    status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    return root, app_context

# ==============================================================================
#                       MAIN APPLICATION EXECUTION
# ==============================================================================

# ------------------------------------------------------------------------------
# Function: main
# Purpose: Entry point of the application. Creates the main window and starts
#          the Tkinter event loop.
# ------------------------------------------------------------------------------
def main():
    """Main function to initialize and run the Secure Steganography application."""
    try:
        # Create the main window and get the application context (though context isn't directly used here)
        root, _ = create_main_window() 
        # Start the Tkinter event loop. This makes the GUI responsive and waits for user interactions.
        root.mainloop()
    except Exception as e:
        # A top-level catch for any unexpected errors during GUI initialization.
        print(f"FATAL ERROR: Could not start the application. {str(e)}")
        # Fallback to a simple Tkinter error message if GUI is partially up.
        try:
            messagebox.showerror("Application Startup Error", f"A critical error occurred: {str(e)}\nThe application will now close.")
        except tk.TclError: # If Tkinter itself hasn't initialized properly
            pass # Just print to console

# ------------------------------------------------------------------------------
# Script Entry Point:
# This ensures that the main() function is called only when the script is
# executed directly (not when imported as a module).
# ------------------------------------------------------------------------------
if __name__ == "__main__":
    main()
