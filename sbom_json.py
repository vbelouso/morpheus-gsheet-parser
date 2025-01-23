import json
import os
import uuid
from itertools import chain
from http import HTTPStatus
import requests
from packageurl import PackageURL
import reports_parser

# Supported Languages
SUPPORTED_LANGUAGES = [
    {'value': "Go", 'children': "Go"},
    {'value': "Python", 'children': "Python"},
    {'value': "Dockerfile", 'children': "Dockerfile"},
    {'value': "Java", 'children': "Java"},
    {'value': "TypeScript", 'children': "TypeScript"},
    {'value': "JavaScript", 'children': "JavaScript"},
]

GITHUB_PREFIX = 'https://github.com/'
GITHUB_API_URL = "https://api.github.com/repos"
MORPHEUS_API_URL = "https://agent-morpheus-rh-shared-morpheus.apps.ai-dev03.kni.syseng.devcluster.openshift.com/scan"
SPDX_SBOM = 'spdx+json'
CYCLONEDX_SBOM = 'cyclonedx+json'
CSV_SBOM = 'CycloneDX'

os.makedirs("requests", exist_ok=True)

def generate_id():
    return str(uuid.uuid4())


def parse_cves_json(json_file):
    with open(json_file, "r") as f:
        cves_data = json.load(f)

    # Flatten table1 and table2 into a single list with table identifiers
    results = []
    for table_name, entries in cves_data.items():
        for entry in entries:
            results.append({
                "table": table_name,
                "cve": entry["cve"],
                "image": entry["image"],
                "sbom_file": entry["sbom_file"],
            })
    return results


def get_repository_info(data):
    properties = data.get('metadata', {}).get('properties', [])
    repo_url = next((prop['value'] for prop in properties if
                     prop['name'] == "syft:image:labels:io.openshift.build.source-location"), None)
    commit_ref = next(
        (prop['value'] for prop in properties if prop['name'] == "syft:image:labels:io.openshift.build.commit.id"),
        None)
    return repo_url, commit_ref


def get_vulnerabilities(cves):
    return [{'vuln_id': cve} for cve in cves]


def get_property(component, property_name):
    properties = component.get('properties', [])
    for prop in properties:
        if prop.get('name') == property_name:
            return prop.get('value')
    return None


def get_components(sbom):
    if sbom is None:
        return []
    components = sbom.get('components', [])
    return [
        {
            'name': component.get('name'),
            'version': component.get('version'),
            'purl': component.get('purl'),
            'system': get_system(component),
        }
        for component in components
    ]


def count_components(data):
    return len(get_components(data))


def get_system(component):
    purl = component.get('purl')
    if purl:
        try:
            package_url = PackageURL.from_string(purl)
            # print ("Package type:", package_url.type)
            return package_url.type
        except ValueError as e:
            print(f"Error parsing purl: {e}")

    prop = get_property(component, "syft:package:type")
    if prop == "go-module":
        return "golang"
    elif prop == "java-archive":
        return "maven"
    # Default to empty string if no valid system is determined (Pydantic validation)
    print(f"System type unknown for component {component.get('name', 'unknown')}")
    return ""

def infer_languages(components):
    language_map = {
        "go": "Go",
        "python": "Python",
        "javascript": "JavaScript",
        "typescript": "TypeScript",
        "dockerfile": "Dockerfile",
        "java": "Java"
    }
    languages = set()
    for component in components:
        for prop in component.get("properties", []):
            if prop["name"] == "syft:package:language":
                lang = prop["value"].lower()
                if lang in language_map:
                    languages.add(language_map[lang])
    return list(languages)


def get_languages_from_repo(repository):
    supported_values = [lang['value'] for lang in SUPPORTED_LANGUAGES]
    if not repository.startswith(GITHUB_PREFIX):
        return []
    repository = repository.removeprefix(GITHUB_PREFIX)
    try:
        url = f"{GITHUB_API_URL}/{repository}/languages"
        headers = {"Accept": "application/vnd.github.v3+json"}
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        return [lang for lang in data.keys() if lang in supported_values]
    except requests.exceptions.RequestException as e:
        print(f"Error fetching languages for {repository}: {e}")
        return []


def get_includes(languages):
    includes_mapping = {
        'Go': ["**/*.go"],
        'Python': [
            "**/*.py",  # All Python source files
            "pyproject.toml",  # PEP 518/517 build system
            "setup.py",  # Setuptools configuration
            "setup.cfg"  # Alternate setuptools configuration
        ],
        'Java': [
            "**/*.java",  # All Java source files
            "settings.gradle",  # Gradle settings file
            "src/main/**/*"  # Main Java source files
        ],
        'JavaScript': [
            "**/*.js",  # All JavaScript source files
            "**/*.jsx",  # JSX files for React
            "webpack.config.js",  # Webpack configuration
            "rollup.config.js",  # Rollup configuration
            "babel.config.js",  # Babel configuration
            ".babelrc",  # Alternate Babel configuration
            ".eslintrc.js",  # ESLint configuration
            ".eslintrc.json",  # Alternate ESLint configuration
            "tsconfig.json",  # TypeScript configuration
            "*.config.js",  # Other JS configuration files
            "*.config.json",  # JSON configuration files
            "public/**/*",  # Public assets (images, icons, etc.)
            "src/**/*"  # Main source files directory
        ],
        'TypeScript': [
            "**/*.ts",  # All TypeScript source files
            "**/*.tsx",  # TSX files for React (TypeScript)
            "tsconfig.json",  # TypeScript configuration
            "tsconfig.*.json",  # TypeScript environment-specific configurations
            "webpack.config.js",  # Webpack configuration
            "webpack.config.ts",  # Webpack configuration in TypeScript
            "rollup.config.js",  # Rollup configuration
            "rollup.config.ts",  # Rollup configuration in TypeScript
            "babel.config.js",  # Babel configuration
            ".babelrc",  # Alternate Babel configuration
            ".eslintrc.js",  # ESLint configuration
            ".eslintrc.json",  # Alternate ESLint configuration
            "*.config.js",  # Other JS configuration files
            "*.config.ts",  # Other TS configuration files
            "*.json",  # JSON configuration files
            "src/**/*",  # Main source files directory
            "public/**/*",  # Public assets (images, icons, etc.)
            "assets/**/*"  # Additional assets directory
        ],
        'Dockerfile': [
            "Dockerfile*",  # Main Dockerfile
            "docker-compose.yml",  # Docker Compose configuration
            "*.dockerfile",  # Additional Dockerfiles with different names
            "*.dockerignore",  # Docker ignore files
            "docker-compose.*.yml",  # Environment-specific Docker Compose files
            "*.sh",  # Shell scripts used in the Docker build process
            "scripts/**/*",  # Any custom scripts used in the Docker setup
            "*.env",  # Environment variable files
            "*.yaml",  # YAML configuration files
            "*.yml",  # YAML configuration files
            "*.json",  # JSON configuration files
            "config/**/*",  # Configuration files relevant to Docker
            "conf.d/**/*"  # Additional configuration directories
        ],
        'Docs': [
            "**/*.md",
            "docs/**/*.rst"
        ]
    }
    includes = [includes_mapping.get(lang, []) for lang in languages]
    return list(chain.from_iterable(includes))


def get_excludes(languages):
    excludes_mapping = {
        "Go": ["test/**/*", "**/vendor/**/*", "go.mod", "go.sum"],
        "Java": [
            "target/**/*", "build/**/*", "*.class", ".gradle/**/*", ".mvn/**/*",
            ".gitignore", "test/**/*", "tests/**/*", "src/test/**/*", "pom.xml",
            "build.gradle"
        ],
        "JavaScript": [
            "node_modules/**/*", "dist/**/*", "build/**/*", "test/**/*",
            "tests/**/*", "example/**/*", "examples/**/*", "package.json",
            "package-lock.json", "yarn.lock"
        ],
        "TypeScript": [
            "node_modules/**/*", "dist/**/*", "build/**/*", "test/**/*",
            "tests/**/*", "example/**/*", "examples/**/*", "package.json",
            "package-lock.json", "yarn.lock"
        ],
        "Python": [
            "tests/**/*", "test/**/*", "venv/**/*", ".venv/**/*", "env/**/*",
            "build/**/*", "dist/**/*", ".mypy_cache/**/*", ".pytest_cache/**/*",
            "__pycache__/**/*", "*.pyc", "*.pyo", "*.pyd", "requirements.txt",
            "Pipfile", "Pipfile.lock"
        ]
    }
    excludes = [excludes_mapping.get(lang, []) for lang in languages]
    return list(chain.from_iterable(excludes))


def build_sbom_info(data):
    sbom_format = data.get('bomFormat')
    sbom_components = get_components(data)
    if sbom_format == CSV_SBOM:
        return {
            '_type': 'manual',
            'packages': [
                {
                    'name': comp.get('name'),
                    'version': comp.get('version'),
                    'purl': comp.get('purl'),
                    'system': comp.get('system')
                }
                for comp in sbom_components
            ]
        }
    return {}


def build_request_json(data, vulns, repository):
    repo_languages = get_languages_from_repo(repository)
    sbom_languages = infer_languages(data.get("components", []))
    all_languages = list(set(repo_languages + sbom_languages))
    data["languages"] = all_languages

    includes = get_includes(all_languages)
    excludes = get_excludes(all_languages)

    sbom_info = build_sbom_info(data)
    repo_url, commit_ref = get_repository_info(data)

    return {
        'scan': {
            'id': generate_id(),
            'vulns': vulns
        },
        'image': {
            'name': data.get('metadata', {}).get('component', {}).get('name'),
            'tag': data.get('metadata', {}).get('component', {}).get('version'),
            'source_info': [
                {
                    'type': "git",
                    'source_type': "code",
                    'git_repo': repo_url,
                    'ref': commit_ref,
                    'include': includes,
                    'exclude': excludes
                },
                {
                    'type': "git",
                    'source_type': "doc",
                    'git_repo': repo_url,
                    'ref': commit_ref,
                    'include': get_includes(["Docs"]),
                    'exclude': []
                }
            ],
            'sbom_info': sbom_info
        }
    }


def send_request_to_morpheus(request):
    try:
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        response = requests.post(url=MORPHEUS_API_URL, json=request, headers=headers)
        response.raise_for_status()
        if response.status_code == HTTPStatus.CREATED:
            print(f"Request successfully sent to Morpheus. Response code: {response.status_code}")
            return True
        print(f"Unexpected response code: {response.status_code}")
        return False
    except requests.exceptions.RequestException as e:
        print(f"Error sending request to the Morpheus: {e}")
        return False

def process_requests_from_cves(cves_file):
    # Read the JSON file
    with open(cves_file, "r") as f:
        cves_data = json.load(f)

    # Process each table
    for table_name, entries in cves_data.items():
        for entry in entries:
            try:
                # Read and process SBOM
                with open(entry["sbom_file"], "r") as sbom:
                    sbom_data = json.load(sbom)

                repository, _ = get_repository_info(sbom_data)
                if not repository:
                    print(f"Repository not found in SBOM for {entry['image']}")
                    continue

                vulns = [{"vuln_id": entry["cve"]}]
                request_json = build_request_json(data=sbom_data, vulns=vulns, repository=repository)
                # Debug
                request_file = os.path.join(
                    "requests",
                    f"{request_json['scan']['id']}.json"
                )
                # Save request JSON
                with open(request_file, 'w') as f:
                    json.dump(request_json, f, indent=2)
                # Send request to server
                if send_request_to_morpheus(request_json):
                    entry["report_id"] = request_json["scan"]["id"]
                    with open(cves_file, 'w') as file:
                        json.dump(cves_data, file, indent=2)
                reports_parser.process_report(request_json["scan"]["id"])
            except FileNotFoundError:
                print(f"SBOM file not found: {entry['sbom_file']}")
            except json.JSONDecodeError:
                print(f"Invalid JSON format in SBOM file: {entry['sbom_file']}")
            except Exception as e:
                print(f"Unexpected error processing {entry['sbom_file']}: {e}")

# Run the processing
process_requests_from_cves(cves_file="cves.json")
