<div id="top"></div>
<br />
<div align="center">
  <h3 align="center">NAC Enforcement Script</h3>
<p align="center">
    Deployment script used for enforcing NAC on one or multiple sites.
    <br />
   </p>
</div><br>
The configuration templates maintained inside this repo use JINJA2. <br /><br />
<font size="2">
:exclamation:	<b>Documentation:  </b><br />
<pre><code><i>The templating language is JINJA2, documentation is located here: 
https://jinja.palletsprojects.com/en/3.0.x/</i>
</pre></code>
  

</pre></code>
</font>

#### Prerequisites


* LogicMonitor API Tokens
  ```
  If using Logic Monitor for deployment method
    ```
* Install the required libraries
  ```
  pip3 install -r requirements.txt
  ```

### Getting Started

Modify the input.json file with the relevant detail.  There are two modes, Logic Monitor mode or Manual mode.

#### Logic Monitor Mode:
- Set the mode inside the input.json file to LM
- Add the SiteID in scope.
<i>NOTE: The IPS field is still mandatory, but ignored</i>

```sh
[
    {
    "mode": "LM",
    "siteID": "25707",
    "vlans": [
        "101",
        "102"
        ],
    "voice_vlan": 100,
    "ips": [
        "10.132.182.2"
    ],
    "country": "Brazil"
    }
]
```

#### Manual Mode:
- Set the mode inside the input.json file to IP
- Add the individual switch IP addresses to the list inside the JSON file.
- Add the Country, following the LogicMonitor convention (Check the settings.json file if in doubt)

```sh
[
    {
    "mode": "IP",
    "siteID": "25707",
    "vlans": [
        "101",
        "102"
        ],
    "voice_vlan": 100,
    "ips": [
        "10.132.182.2"
    ],
    "country": "Brazil"
    }
]
```

