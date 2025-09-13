import time
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.chrome.service import Service as ChromeService
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import NoSuchElementException
from datetime import datetime, timezone
import json
import re
import csv
import os
import undetected_chromedriver as uc
from selenium.webdriver.chrome.options import Options
from dotenv import load_dotenv
import os

load_dotenv()
USERNAME = os.getenv("USERNAME")
PASSWORD = os.getenv("PASSWORD")
EMAIL = os.getenv("EMAIL")

def auto_login(driver, username, password,email):
    login_url = "https://x.com/login"
    driver.get(login_url)

    WebDriverWait(driver, 10).until(
        EC.presence_of_element_located((By.NAME, "text")))
    username_input = driver.find_element(By.NAME, "text")
    username_input.send_keys(username)
    username_input.send_keys(Keys.RETURN)

    try:
        WebDriverWait(driver, 5).until(
            EC.presence_of_element_located((By.NAME, "text")))
        email_input = driver.find_element(By.NAME, "text")
        email_input.send_keys(email)
        email_input.send_keys(Keys.RETURN)
    except Exception as e:
        print("Email input step skipped:", e)

    WebDriverWait(driver, 10).until(
        EC.presence_of_element_located((By.NAME, "password")))
    password_input = driver.find_element(By.NAME, "password")
    password_input.send_keys(password)
    password_input.send_keys(Keys.RETURN)
    WebDriverWait(driver, 10).until(EC.url_contains("home"))


    time.sleep(10)

DATE_FILE = 'last_scraped_dates_1.json'
HASH_FILE = 'twitter.csv'

def load_last_dates():
    try:
        with open(DATE_FILE, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def save_last_dates(data):
    with open(DATE_FILE, 'w') as f:
        json.dump(data, f, indent=4)

def save_hash_to_csv(username, hash_value):
    file_exists = os.path.isfile(HASH_FILE)
    
    with open(HASH_FILE, 'a', newline='') as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(['username', 'md5_hash'])
        writer.writerow([username, hash_value])

def find_md5_hashes(text):
    md5_pattern = r'\b[a-fA-F0-9]{32}\b'
    return re.findall(md5_pattern, text)

def scrape_for_md5_hashes(driver,username):
    last_dates = load_last_dates()
    last_scraped_date_str = last_dates.get(username)
    
    if last_scraped_date_str:
        print(f"User '{username}' found. Last update: {last_scraped_date_str}.")
    else:
        print(f"User '{username}' not found. Performing initial scrape.")

    last_scraped_date = None
    if last_scraped_date_str:
        last_scraped_date = datetime.fromisoformat(last_scraped_date_str.replace('Z', '+00:00'))

    search_url = f"https://x.com/{username}"
    driver.get(search_url)
    driver.maximize_window()
    print("WebDriver initiated. Looking for new posts...")
    time.sleep(10)
    
    new_posts_this_run = []
    processed_post_texts = set()
    last_height = driver.execute_script("return document.body.scrollHeight")
    stop_scraping = False
    count=0
    try:
        while not stop_scraping:
            posts_on_page = driver.find_elements(By.XPATH, '//article[@role="article"]')
            
            for post in posts_on_page:
                post_text = post.text
                if post_text and post_text not in processed_post_texts:
                    count+=1
                    processed_post_texts.add(post_text)
                    try:
                        time_element = post.find_element(By.XPATH, './/time')
                        post_date_str = time_element.get_attribute('datetime')
                        post_date = datetime.fromisoformat(post_date_str.replace('Z', '+00:00'))

                        if last_scraped_date and post_date <= last_scraped_date:
                            print("Found an old post. All newer posts have been processed.")
                            stop_scraping = True
                            break
                        
                        new_posts_this_run.append({'date': post_date_str})

                        hashes = find_md5_hashes(post_text)
                        if hashes:
                            print(f"Found {len(hashes)} hash(es) in a post!")
                            for md5_hash in hashes:
                                save_hash_to_csv(username, md5_hash)

                    except NoSuchElementException:
                        continue
            
            if stop_scraping:
                break

            driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
            time.sleep(2)
            
            new_height = driver.execute_script("return document.body.scrollHeight")
            if new_height == last_height:
                print("Reached the end of the page.")
                break
            last_height = new_height

    except Exception as e:
        print(f"An error occurred: {e}")
        
    if new_posts_this_run:
        new_posts_this_run.sort(key=lambda x: x['date'], reverse=True)
        newest_post_date = new_posts_this_run[0]['date']
        last_dates[username] = newest_post_date
        save_last_dates(last_dates)
        print(f"Updated last scrape date for '{username}' to {newest_post_date}.")
        
    else:
        print("No new posts found.")

    print(f"count: {count}")

def scrape_posts():
    chrome_options = Options()
    user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
    chrome_options.add_argument(f'user-agent={user_agent}')

    usernames=["ReBensk","JAMESWT_WT","banthisguy9349","MariusSheppard","LukasStefanko","cryptax","ni_fi_70","Nethanella","akaclandestine","androidmalware2"]
    print("HERE")
    driver = webdriver.Chrome(service=ChromeService(ChromeDriverManager().install()),options=chrome_options)
    print("HERE")
    username = USERNAME
    password = PASSWORD
    email = EMAIL

    
    auto_login(driver,username,password,email)

    for username in usernames:
        scrape_for_md5_hashes(driver,username)
    driver.quit()
    
if __name__ == "__main__":
    scrape_posts()