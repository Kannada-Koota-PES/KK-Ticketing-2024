import traceback
from typing import Optional

import requests_html
from bs4 import BeautifulSoup


def get_know_your_class_and_section(username: str, session: Optional[requests_html.HTMLSession] = None, csrf_token: Optional[str] = None):
    """
    Gets the student details from Know Your Class and Section
    """

    if not session:
        session = requests_html.HTMLSession()

    if not csrf_token:
        home_url = "https://www.pesuacademy.com/Academy/"
        response = session.get(home_url)
        soup = BeautifulSoup(response.text, "lxml")
        csrf_token = soup.find("meta", attrs={"name": "csrf-token"})["content"]

    try:
        response = session.post(
            "https://www.pesuacademy.com/Academy/getStudentClassInfo",
            headers={
                "authority": "www.pesuacademy.com",
                "accept": "*/*",
                "accept-language": "en-IN,en-US;q=0.9,en-GB;q=0.8,en;q=0.7",
                "content-type": "application/x-www-form-urlencoded",
                "origin": "https://www.pesuacademy.com",
                "referer": "https://www.pesuacademy.com/Academy/",
                "sec-ch-ua": '"Not.A/Brand";v="8", "Chromium";v="114", "Google Chrome";v="114"',
                "sec-ch-ua-mobile": "?0",
                "sec-ch-ua-platform": '"Linux"',
                "sec-fetch-dest": "empty",
                "sec-fetch-mode": "cors",
                "sec-fetch-site": "same-origin",
                "x-csrf-token": csrf_token,
                "x-requested-with": "XMLHttpRequest"
            },
            data={
                "loginId": username
            }
        )
    except Exception:
        # logging.error(f"Unable to get profile from Know Your Class and Section: {traceback.format_exc()}")
        print(f"Unable to get profile from Know Your Class and Section: {traceback.format_exc()}")
        return {}

    soup = BeautifulSoup(response.text, "html.parser")
    profile = dict()
    for th, td in zip(soup.find_all("th"), soup.find_all("td")):
        key = th.text.strip()
        key = key.replace(" ", "_").lower()
        value = td.text.strip()
        profile[key] = value

    return profile


if __name__ == "__main__":
    print(get_know_your_class_and_section("email_or_phone_number"))