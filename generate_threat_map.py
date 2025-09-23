import requests
import json
import random
import datetime
import shodan
import base64
import os

# --- CONFIGURATION ---
# SECURE: The API key is now read from an environment variable (or a GitHub Secret).
SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY")

OUTPUT_SVG_FILENAME = "threat-map.svg"

SHODAN_QUERY = "has_vuln:true"
NUMBER_OF_RESULTS_TO_FETCH = 200 
IPS_PER_CONTINENT = 10
SVG_WIDTH = 1024
SVG_HEIGHT = 512

# Target coordinates for each continent's data hub
CONTINENT_TARGETS = {
    "North America": (40.7128, -74.0060),  # New York City, USA
    "Europe": (50.1109, 8.6821),          # Frankfurt, Germany
    "Asia": (35.6895, 139.6917),          # Tokyo, Japan
    "South America": (-23.5505, -46.6333), # São Paulo, Brazil
    "Africa": (-26.2041, 28.0473),         # Johannesburg, South Africa
    "Oceania": (-33.8688, 151.2093)       # Sydney, Australia
}

# --- MAPPING & STYLES ---
COUNTRY_TO_CONTINENT = {
    'US': 'North America', 'CA': 'North America', 'MX': 'North America', 'GL': 'North America', 'GT': 'North America', 'CR': 'North America', 'PA': 'North America',
    'AR': 'South America', 'BR': 'South America', 'BO': 'South America', 'CL': 'South America', 'CO': 'South America', 'EC': 'South America', 'PY': 'South America', 'PE': 'South America', 'UY': 'South America', 'VE': 'South America',
    'AL': 'Europe', 'AD': 'Europe', 'AM': 'Europe', 'AT': 'Europe', 'BY': 'Europe', 'BE': 'Europe', 'BA': 'Europe', 'BG': 'Europe', 'CH': 'Europe', 'CY': 'Europe', 'CZ': 'Europe', 'DE': 'Europe', 'DK': 'Europe', 'EE': 'Europe', 'ES': 'Europe', 'FI': 'Europe', 'FR': 'Europe', 'GB': 'Europe', 'GE': 'Europe', 'GR': 'Europe', 'HR': 'Europe', 'HU': 'Europe', 'IE': 'Europe', 'IS': 'Europe', 'IT': 'Europe', 'LT': 'Europe', 'LU': 'Europe', 'LV': 'Europe', 'MC': 'Europe', 'MK': 'Europe', 'MT': 'Europe', 'NO': 'Europe', 'NL': 'Europe', 'PL': 'Europe', 'PT': 'Europe', 'RO': 'Europe', 'RS': 'Europe', 'RU': 'Europe', 'SE': 'Europe', 'SI': 'Europe', 'SK': 'Europe', 'SM': 'Europe', 'UA': 'Europe', 'VA': 'Europe',
    'CN': 'Asia', 'HK': 'Asia', 'IN': 'Asia', 'ID': 'Asia', 'IR': 'Asia', 'IQ': 'Asia', 'JP': 'Asia', 'KG': 'Asia', 'KH': 'Asia', 'KP': 'Asia', 'KR': 'Asia', 'KZ': 'Asia', 'LA': 'Asia', 'LK': 'Asia', 'MM': 'Asia', 'MN': 'Asia', 'MY': 'Asia', 'NP': 'Asia', 'PH': 'Asia', 'PK': 'Asia', 'SA': 'Asia', 'SG': 'Asia', 'TH': 'Asia', 'TJ': 'Asia', 'TM': 'Asia', 'TR': 'Asia', 'TW': 'Asia', 'UZ': 'Asia', 'VN': 'Asia', 'AE': 'Asia', 'IL': 'Asia', 'QA': 'Asia', 'OM': 'Asia',
    'AU': 'Oceania', 'NZ': 'Oceania', 'FJ': 'Oceania', 'PG': 'Oceania',
    'DZ': 'Africa', 'AO': 'Africa', 'BW': 'Africa', 'BI': 'Africa', 'CM': 'Africa', 'CF': 'Africa', 'TD': 'Africa', 'CG': 'Africa', 'CD': 'Africa', 'DJ': 'Africa', 'EG': 'Africa', 'GQ': 'Africa', 'ET': 'Africa', 'GA': 'Africa', 'GM': 'Africa', 'GH': 'Africa', 'GN': 'Africa', 'KE': 'Africa', 'LS': 'Africa', 'LR': 'Africa', 'LY': 'Africa', 'MG': 'Africa', 'MW': 'Africa', 'ML': 'Africa', 'MR': 'Africa', 'MA': 'Africa', 'MZ': 'Africa', 'NA': 'Africa', 'NE': 'Africa', 'NG': 'Africa', 'RW': 'Africa', 'SN': 'Africa', 'SL': 'Africa', 'SO': 'Africa', 'ZA': 'Africa', 'SS': 'Africa', 'SD': 'Africa', 'TZ': 'Africa', 'TG': 'Africa', 'TN': 'Africa', 'UG': 'Africa', 'ZM': 'Africa', 'ZW': 'Africa',
}

ATTACK_COLORS = ["#ff4136", "#f012be", "#00aaff", "#39cccc", "#ffdc00"]
TEXT_COLOR = "#cccccc"
LIST_BG_COLOR = "#1a1a1a"

def find_background_image():
    """Checks for map.png or map.jpg in the script's directory."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    for ext in ['.png', '.jpg', '.jpeg']:
        path = os.path.join(script_dir, f"map{ext}")
        if os.path.exists(path):
            print(f"Found background image: {path}")
            return path
    print("Warning: No 'map.png' or 'map.jpg' found in the root directory.")
    return None

def image_to_base64(image_path):
    """Reads an image and converts it to a Base64 encoded data URI."""
    try:
        with open(image_path, "rb") as image_file:
            encoded_string = base64.b64encode(image_file.read()).decode('utf-8')
        ext = os.path.splitext(image_path)[1].lower()
        if ext == '.png':
            return f"data:image/png;base64,{encoded_string}"
        elif ext in ['.jpg', '.jpeg']:
            return f"data:image/jpeg;base64,{encoded_string}"
        else:
            print(f"Warning: Unsupported image format '{ext}'.")
            return None
    except Exception as e:
        print(f"Error encoding image: {e}")
        return None

def get_ips_from_shodan():
    """Fetches IPs from Shodan and sorts them by continent."""
    if not SHODAN_API_KEY:
        print("Error: SHODAN_API_KEY environment variable not set. Please create a GitHub Secret.")
        return {}
    print("Fetching and sorting IPs from Shodan by continent...")
    try:
        api = shodan.Shodan(SHODAN_API_KEY)
        results = api.search(SHODAN_QUERY, limit=NUMBER_OF_RESULTS_TO_FETCH)
        continent_ips = { name: [] for name in CONTINENT_TARGETS.keys() }
        for result in results['matches']:
            country_code = result.get('location', {}).get('country_code')
            continent = COUNTRY_TO_CONTINENT.get(country_code)
            if continent and len(continent_ips[continent]) < IPS_PER_CONTINENT:
                continent_ips[continent].append(result['ip_str'])
        print("IP distribution found:")
        for continent, ips in continent_ips.items():
            if ips: print(f" - {continent}: {len(ips)} IPs")
        return continent_ips
    except shodan.APIError as e:
        print(f"Error querying Shodan: {e}")
        return {}

def get_geolocations_batch(ips):
    """Gets geolocation data for a list of IPs using the batch API."""
    if not ips: return []
    print(f"Geolocating {len(ips)} IPs using the batch API...")
    try:
        response = requests.post("http://ip-api.com/batch?fields=lat,lon,country,query,status", json=ips, timeout=15)
        response.raise_for_status()
        return [item for item in response.json() if item.get("status") == "success"]
    except (requests.exceptions.RequestException, json.JSONDecodeError) as e:
        print(f"Error during batch geolocation: {e}")
        return []

def latlon_to_svg(lat, lon):
    """Converts latitude and longitude to SVG coordinates, calibrated for map.jpg."""
    # The scale is derived from SVG_WIDTH / 360 degrees
    SCALE = 2.8444
    
    # Fine-tuned offsets to align the projection with the background image
    X_OFFSET = -45
    Y_OFFSET = 60

    x = (lon + 180) * SCALE + X_OFFSET
    y = (lat * -1 + 90) * SCALE + Y_OFFSET
    
    return x, y

def generate_svg(attack_data_by_continent, bg_image_base64):
    """Generates the final SVG string."""
    svg = (
        f'<svg width="{SVG_WIDTH}" height="{SVG_HEIGHT}" viewBox="0 0 {SVG_WIDTH} {SVG_HEIGHT}" '
        'xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">'
    )
    svg += f"""
    <style>
        .attack-dot, .origin-dot {{ filter: url(#glow); }}
        .target-dot {{ filter: url(#glow); animation: pulse 2.5s ease-in-out infinite; }}
        .text {{ font-family: monospace; fill: {TEXT_COLOR}; }}
        @keyframes pulse {{ 0% {{ r: 4; opacity: 1; }} 50% {{ r: 8; opacity: 0.7; }} 100% {{ r: 4; opacity: 1; }} }}
    </style>"""
    list_x = SVG_WIDTH - 250
    list_y = 20
    list_height = 135
    svg += f"""
    <defs>
        <filter id="glow" x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur stdDeviation="3" result="coloredBlur"/><feMerge><feMergeNode in="coloredBlur"/><feMergeNode in="SourceGraphic"/></feMerge>
        </filter>
        <clipPath id="list-clip">
            <rect x="{list_x + 15}" y="{list_y + 40}" width="200" height="{list_height}"/>
        </clipPath>
    </defs>"""
    
    if bg_image_base64:
        svg += f'<image href="{bg_image_base64}" x="0" y="0" width="100%" height="100%"/>'
    else:
        svg += '<rect width="100%" height="100%" fill="#0a0a0a"/>'

    timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    svg += f'<text x="20" y="40" class="text" font-size="22">LIVE THREAT MAP</text>'
    svg += f'<text x="20" y="60" class="text" font-size="12" fill="#888888">Last updated: {timestamp}</text>'

    for lat, lon in CONTINENT_TARGETS.values():
        target_x, target_y = latlon_to_svg(lat, lon)
        svg += f'<circle cx="{target_x}" cy="{target_y}" fill="#00ff99" class="target-dot"/>'

    all_attacks = [attack for attacks in attack_data_by_continent.values() for attack in attacks]
    
    if all_attacks:
        num_items = len(all_attacks)
        item_height = 14
        total_scroll_height = num_items * item_height
        animation_duration = num_items * 1.5

        svg += f'<rect x="{list_x}" y="{list_y}" width="230" height="180" fill="{LIST_BG_COLOR}" fill-opacity="0.7" rx="10"/>'
        svg += f'<text x="{list_x + 15}" y="{list_y + 30}" class="text" font-size="14" font-weight="bold">RECENT THREATS</text>'
        svg += f'<g clip-path="url(#list-clip)"><g>'
        
        sorted_attack_data = sorted(all_attacks, key=lambda x: x['query'])
        
        for i, attack in enumerate(sorted_attack_data * 2):
            country = attack.get('country', 'Unk')
            country_short = (country[:11] + '..') if len(country) > 13 else country
            ip_text = f"{attack['query']:<15} - {country_short}"
            text_y = list_y + 55 + (i * item_height)
            svg += f'<text x="{list_x + 15}" y="{text_y}" class="text" font-size="11">{ip_text}</text>'
        
        svg += (f'<animateTransform attributeName="transform" type="translate" from="0 0" to="0 -{total_scroll_height}" '
                f'dur="{animation_duration}s" repeatCount="indefinite"/>')
        svg += f'</g></g>'

    path_counter = 0
    continent_names = list(CONTINENT_TARGETS.keys())
    for continent, attacks in attack_data_by_continent.items():
        for attack in attacks:
            if random.random() < 0.5:
                other_continents = [c for c in continent_names if c != continent]
                target_continent = random.choice(other_continents) if other_continents else continent
            else:
                target_continent = continent

            target_lat, target_lon = CONTINENT_TARGETS[target_continent]
            target_x, target_y = latlon_to_svg(target_lat, target_lon)
            source_x, source_y = latlon_to_svg(attack["lat"], attack["lon"])
            color = random.choice(ATTACK_COLORS)
            ctrl_x = (source_x + target_x) / 2 + (target_y - source_y) * random.uniform(0.2, 0.5)
            ctrl_y = (source_y + target_y) / 2 - (target_x - source_x) * random.uniform(0.2, 0.5)
            path_data = f"M{source_x},{source_y} Q{ctrl_x},{ctrl_y} {target_x},{target_y}"
            path_id = f"path{path_counter}"
            
            svg += f'<circle cx="{source_x}" cy="{source_y}" r="3" fill="{color}" class="origin-dot"/>'
            svg += f'<path id="{path_id}" d="{path_data}" stroke="{color}" stroke-width="1.5" stroke-opacity="0.4" fill="none"/>'
            delay = round(random.uniform(0, 5), 2)
            duration = round(random.uniform(3, 6), 2)
            svg += (
                f'<circle class="attack-dot" r="3.5" fill="{color}">'
                f'<animateMotion dur="{duration}s" repeatCount="indefinite" begin="{delay}s" calcMode="spline" keyTimes="0;1" keySplines="0.4 0 0.2 1">'
                f'<mpath xlink:href="#{path_id}"/></animateMotion></circle>'
            )
            path_counter += 1

    svg += '</svg>'
    return svg

def main():
    """Main function to generate the threat map."""
    print("Starting threat map generation...")
    
    continent_ips = get_ips_from_shodan()
    if not any(continent_ips.values()):
        print("No IPs found from Shodan to process. Exiting.")
        return
        
    all_ips_flat = [ip for ip_list in continent_ips.values() for ip in ip_list]
    geolocated_data = get_geolocations_batch(all_ips_flat)
    
    print(f"Successfully geolocated {len(geolocated_data)} IPs.")
    if not geolocated_data:
        print("Could not geolocate any IPs. Exiting.")
        return

    geolocated_data_by_continent = { name: [] for name in CONTINENT_TARGETS.keys() }
    for data in geolocated_data:
        ip = data['query']
        for continent, ip_list in continent_ips.items():
            if ip in ip_list:
                geolocated_data_by_continent[continent].append(data)
                break
    
    image_path = find_background_image()
    bg_image_base64 = image_to_base64(image_path) if image_path else None

    svg_content = generate_svg(geolocated_data_by_continent, bg_image_base64)
    try:
        with open(OUTPUT_SVG_FILENAME, "w", encoding="utf-8") as f:
            f.write(svg_content)
        print(f"Successfully generated and saved '{OUTPUT_SVG_FILENAME}'")
    except IOError as e:
        print(f"Error writing SVG file: {e}")

if __name__ == "__main__":
    main()

