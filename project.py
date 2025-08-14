import tkinter as tk
import random
import string
from tkinter import ttk

def main():
    global root, length_entry, uppercase_var, lowercase_var, digits_var, symbols_var, result_var, strength_var, strength_label

    root = tk.Tk()
    root.title("Password Generator")
    root.geometry("400x400")
    root.config(padx=20, pady=20)

    tk.Label(root, text="Password Length:").pack(anchor="w")
    length_entry = tk.Entry(root)
    length_entry.pack(fill="x", pady=5)

    uppercase_var = tk.BooleanVar(value=True)
    lowercase_var = tk.BooleanVar(value=True)
    digits_var = tk.BooleanVar(value=True)
    symbols_var = tk.BooleanVar(value=True)

    tk.Checkbutton(root, text="Include Uppercase", variable=uppercase_var).pack(anchor="w")
    tk.Checkbutton(root, text="Include Lowercase", variable=lowercase_var).pack(anchor="w")
    tk.Checkbutton(root, text="Include Numbers", variable=digits_var).pack(anchor="w")
    tk.Checkbutton(root, text="Include Symbols", variable=symbols_var).pack(anchor="w")

    style = ttk.Style()
    style.configure("TButton", font=("Helvetica", 12, "bold"), foreground="white", background="blue")
    style.map("TButton",
              foreground=[('pressed', 'white'), ('active', 'white')],
              background=[('pressed', '!disabled', 'darkblue'), ('active', 'blue')])

    btn = ttk.Button(root, text="Generate Password", command=generate_password, style="TButton")
    btn.pack(pady=15)

    result_var = tk.StringVar()
    result_entry = tk.Entry(root, textvariable=result_var, font=("Helvetica", 14), justify="center")
    result_entry.pack(fill="x", pady=5)

    copy_btn = tk.Button(root, text="Copy to Clipboard", command=copy_to_clipboard)
    copy_btn.pack(pady=10)

    strength_var = tk.StringVar()
    strength_label = tk.Label(root, textvariable=strength_var, font=("Helvetica", 12, "bold"))
    strength_label.pack()

    root.mainloop()



def generate_password():
    global length_entry, uppercase_var, lowercase_var, digits_var, symbols_var, result_var, strength_var, strength_label
    try:
        length = int(length_entry.get())
        if length < 4 or length > 50:
            result_var.set("Length must be 4-50")
            return
    except ValueError:
        result_var.set("Enter a valid number")
        return

    char_pool = ""
    if uppercase_var.get():
        char_pool += string.ascii_uppercase
    if lowercase_var.get():
        char_pool += string.ascii_lowercase
    if digits_var.get():
        char_pool += string.digits
    if symbols_var.get():
        char_pool += string.punctuation

    if not char_pool:
        result_var.set("Select at least one character set!")
        return

    password = ''.join(random.choice(char_pool) for _ in range(length))
    result_var.set(password)
    update_strength(password)

def copy_to_clipboard():
    global root, result_var
    root.clipboard_clear()
    root.clipboard_append(result_var.get())

def update_strength(pw):
    global uppercase_var, lowercase_var, digits_var, symbols_var, strength_var, strength_label
    score = 0
    length = len(pw)
    categories = [uppercase_var.get(), lowercase_var.get(), digits_var.get(), symbols_var.get()]
    score += sum(categories) * 10
    if length >= 12:
        score += 20
    elif length >= 8:
        score += 10

    if score >= 40:
        strength_var.set("Strength: Strong")
        strength_label.config(fg="green")
    elif score >= 25:
        strength_var.set("Strength: Medium")
        strength_label.config(fg="orange")
    else:
        strength_var.set("Strength: Weak")
        strength_label.config(fg="red")


def password(length, upper, lower, digits, symbols):
    import string, random
    pool = ""
    if upper:
        pool += string.ascii_uppercase
    if lower:
        pool += string.ascii_lowercase
    if digits:
        pool += string.digits
    if symbols:
        pool += string.punctuation
    if not pool:
        raise ValueError("No character types selected.")
    return ''.join(random.choice(pool) for _ in range(length))

if __name__ == "__main__":
    main()

