# Security Infrastructure and Automation Platform

## Project Overview

The Security Infrastructure and Automation Platform is a comprehensive security assessment framework designed to automate and streamline the entire security testing workflow. Built with Django and modern security tools, this platform integrates reconnaissance, vulnerability scanning, exploit matching, and reporting into a unified, automated pipeline.

This project aims to solve key challenges in security assessment:
- Eliminate manual coordination between different security tools
- Provide consistent and thorough vulnerability detection
- Automate repetitive security testing tasks
- Generate comprehensive, actionable reports
- Match vulnerabilities with relevant exploits for validation

## Core Features

This platform integrates several key modules to provide a comprehensive security assessment solution:

### 1. Reconnaissance Module

The reconnaissance module provides comprehensive target discovery capabilities:

- **Advanced Subdomain Enumeration**
  - Multiple discovery techniques (DNS enumeration, brute forcing)
  - Subdomain validation and active status checking
  - Automatic IP resolution and HTTP service detection
  - Results storage in database for future reference

- **Comprehensive Port Scanning**
  - Integration with Nmap for reliable port discovery
  - Multiple scan types (quick, standard, full)
  - TCP and UDP port scanning with service detection
  - Banner grabbing for service identification
  - Fallback mechanisms for improved reliability

- **Service Identification**
  - Detailed service fingerprinting
  - Version detection for known services
  - Risk categorization based on service type
  - Automatic vulnerability flagging for high-risk services

### 2. Vulnerability Assessment

The vulnerability module provides a multi-layered approach to finding security issues:

- **Multiple Scanner Integration**
  - OWASP ZAP integration for web application scanning
  - Nuclei scanning with template-based detection
  - Internal scanner for basic security checks
  - Support for different scan profiles (quick, standard, full)

- **Advanced Correlation Engine**
  - Cross-reference findings from multiple scanners
  - Intelligent deduplication of similar vulnerabilities
  - Unified vulnerability database with normalized data
  - Source tracking for multi-scanner findings

- **Risk Scoring System**
  - CVSS (Common Vulnerability Scoring System) implementation
  - Custom risk calculation algorithms
  - Age-based risk amplification
  - Categorization by severity (Critical, High, Medium, Low)

### 3. Exploit Integration

The exploit manager provides capabilities to match vulnerabilities with potential exploits:

- **ExploitDB Integration**
  - Direct integration with ExploitDB dataset
  - Local database for exploit metadata
  - Regular updates via synchronization command
  - Searchable exploit repository

- **Intelligent Matching Algorithm**
  - Classification-based vulnerability-to-exploit matching
  - Multiple matching strategies for different vulnerability types
  - Keyword extraction and content-based matching
  - Fallback matching for edge cases

- **Confidence Scoring**
  - Relevance scoring for exploit matches
  - Match quality indicators
  - User feedback collection for match improvement
  - Detailed match reasoning

### 4. Automation and Workflow

The automation module orchestrates the entire security testing process:

- **Workflow Orchestrator**
  - End-to-end scanning workflow
  - Task dependency management
  - Failure handling and recovery
  - Progress tracking and status updates

- **Scheduling System**
  - Regular scan scheduling
  - Custom recurring schedules (daily, weekly, monthly)
  - Schedule management interface
  - Scheduled task tracking

- **Notification System**
  - Email notifications for critical findings
  - Workflow completion alerts
  - Task failure notifications
  - Report ready notifications

### 5. Reporting System

The reporting module provides comprehensive security reporting:

- **Multi-Format Reports**
  - HTML report generation
  - PDF report generation
  - JSON output for integration
  - Customizable report types (basic, detailed, executive)

- **Vulnerability Presentation**
  - Detailed vulnerability information
  - Evidence and proof of concept
  - Severity classification
  - Mitigation recommendations
  - Exploit match suggestions

- **Executive Summaries**
  - Risk-level assessment
  - Critical findings highlight
  - Actionable recommendations
  - Progress tracking between scans

### 6. Network Visualization

The network visualization module provides graphical representation of network architecture:

- **Network Topology Mapping**
  - Visual representation of network structure
  - Node and connection visualization
  - Subdomain relationships
  - Service mapping

- **Interactive Network Map**
  - Visual exploration of network structure
  - Relationship visualization
  - Target-centered mapping
  - Service and vulnerability highlighting



## Technical Architecture

### System Components

The platform is built with a modular architecture based on the following Django apps:

- **reconnaissance**: Handles subdomain enumeration, port scanning, and service identification
- **vulnerability**: Manages vulnerability scanning, correlation, and risk scoring
- **exploit_manager**: Handles exploit database and matching algorithms
- **automation**: Coordinates workflows, scheduling, and notifications
- **reporting**: Generates security reports in various formats
- **network_visualization**: Creates visual representations of network topology

### Technology Stack

- **Backend Framework**: Django (Python)
- **Database**: SQLite (development), supports other Django-compatible databases
- **External Tools**:
  - OWASP ZAP (via Docker container and API integration)
  - Nuclei (integrated via subprocess)
  - Nmap (via Python libraries)
- **Containerization**: Docker and Docker Compose
- **Notification**: Email via Django's email system

### Data Flow

1. **Target Input**: Domain/URL provided by user or scheduler
2. **Reconnaissance**: Discovery of subdomains, ports, and services
3. **Vulnerability Scanning**: Multiple scanners assess security issues
4. **Correlation**: Findings are deduplicated and normalized
5. **Exploit Matching**: Vulnerabilities matched with potential exploits
6. **Reporting**: Comprehensive report generation with findings
7. **Notification**: Alerts on critical issues and workflow completion

## Installation Guide

### Prerequisites

- Python 3.10 or higher
- Docker and Docker Compose
- Git
- Nuclei (optional, for template-based scanning)

### Step-by-Step Installation

1. **Clone the repository**

```bash
git clone https://github.com/yourusername/Security-Infrastructure-Automation-Platform.git
cd Security-Infrastructure-Automation-Platform
```

2. **Create a virtual environment**

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install dependencies**

```bash
pip install -r requirements.txt
```

4. **Initialize the database**

```bash
python manage.py migrate
```

5. **Create directories for logs and results**

```bash
mkdir -p logs zap/data zap/scripts
```

6. **Start the ZAP container (required for web application scanning)**

```bash
docker-compose up -d zap
```

7. **Run the development server**

```bash
python manage.py runserver
```

8. **Initialize exploit database (optional but recommended)**

```bash
python manage.py sync_exploits --limit 1000
```

### Configuration Options

Key configuration options in `settings.py`:

- **ZAP Settings**: Connection details for OWASP ZAP
- **Nuclei Settings**: Path to Nuclei binary and templates
- **Email Settings**: Configuration for notifications
- **Automation Settings**: Default processing intervals

## Usage Guide

### Starting a Basic Scan

1. Navigate to the main dashboard
2. Click "New Scan" and enter a target domain/URL
3. Select scan profile (quick, standard, full)
4. Click "Start Scan" to begin the workflow
5. Monitor progress on the workflow status page

### Viewing Results

1. From the dashboard, select the completed scan
2. View the summary of findings by severity
3. Explore individual vulnerabilities with details
4. Check exploit matches for each vulnerability
5. View the network map showing discovered infrastructure

### Report Generation

1. From a completed scan, click "Generate Report"
2. Select report type (basic, detailed, executive)
3. Choose format (HTML, PDF)
4. Download or view the generated report

### Scheduling Regular Scans

1. Navigate to the Automation section
2. Click "Create Schedule"
3. Select target, frequency, and notification options
4. Save the schedule to enable regular scanning

### Exploit Matching

1. From a vulnerability detail page, click "Find Exploits"
2. Review suggested exploits with confidence scores
3. Select an exploit to view details

## Security Considerations

This platform is designed for legitimate security testing with proper authorization. Usage guidelines:

- Only scan systems you own or have explicit permission to test
- Configure rate limiting to avoid overwhelming target systems
- Review and follow responsible disclosure practices
- Never use exploits on production systems without proper authorization
- Secure access to the platform to prevent unauthorized usage

## Troubleshooting

Common issues and solutions:

- **ZAP Connection Failures**: Ensure the ZAP container is running (`docker ps`)
- **Scan Timeouts**: Adjust timeout settings for large targets
- **Database Locks**: Ensure proper connection closure in long operations
- **Missing Dependencies**: Check all required Python packages are installed
- **Port Scanning Issues**: Verify proper permissions for Nmap

## Development and Extending

### Adding a New Scanner

1. Create a new scanner class implementing the scanner interface
2. Integrate with the `unified_scanner.py` module
3. Update the correlation engine to handle new data format
4. Add UI elements for scanner configuration

### Creating Custom Reports

1. Add new templates to the reporting module
2. Implement a new report generator class
3. Register the report type in the reporting system
4. Update the UI to offer the new report type

## API Documentation

The platform provides a comprehensive RESTful API for programmatic integration and automation. This section details all available endpoints, request/response formats.

### Reconnaissance API

#### List Subdomains

```
GET /recon/subdomains/?domain={domain}
```

Parameters:
- `domain` (required): Target domain to list subdomains for

Response:
```json
{
    "count": 42,
    "next": "http://example.com/api/recon/subdomains/?domain=example.com&page=2",
    "previous": null,
    "results": [
        {
            "domain": "example.com",
            "subdomain": "admin.example.com",
            "ip_address": "192.168.1.1",
            "discovered_date": "2025-01-15T14:30:00Z",
            "is_active": true
        },
        ...
    ]
}
```

#### List Port Scans

```
GET /recon/ports/?host={host}
```

Parameters:
- `host` (required): Hostname or IP address to list port scans for

Response:
```json
{
    "count": 25,
    "next": null,
    "previous": null,
    "results": [
        {
            "host": "example.com",
            "port": 80,
            "service": "http",
            "state": "open",
            "protocol": "tcp",
            "banner": "nginx/1.18.0",
            "scan_date": "2025-01-15T14:35:00Z"
        },
        ...
    ]
}
```

#### Start Reconnaissance Scan

```
POST /recon/scan/
Content-Type: application/json

{
    "target": "example.com",
    "scan_type": "standard",  // "quick", "standard", "full"
    "include_subdomain_enum": true,
    "include_port_scan": true,
    "include_service_id": true
}
```

Response:
```json
{
    "id": 123,
    "status": "pending",
    "target": "example.com",
    "created_at": "2025-01-15T14:40:00Z"
}
```

#### Get Reconnaissance Scan Status

```
GET /recon/scan/{scan_id}/
```

Response:
```json
{
    "id": 123,
    "status": "completed",  // "pending", "in_progress", "completed", "failed"
    "target": "example.com",
    "created_at": "2025-01-15T14:40:00Z",
    "completed_at": "2025-01-15T14:50:00Z",
    "results_summary": {
        "subdomains_found": 42,
        "open_ports": 8,
        "services_identified": 8
    }
}
```

### Vulnerability API

#### List Vulnerabilities

```
GET /vulnerability/list/?target={target}
```

Parameters:
- `target` (required): Target to list vulnerabilities for
- `severity` (optional): Filter by severity (CRITICAL, HIGH, MEDIUM, LOW)
- `is_fixed` (optional): Filter by fix status (true, false)

Response:
```json
{
    "count": 18,
    "next": null,
    "previous": null,
    "results": [
        {
            "id": 456,
            "target": "example.com",
            "name": "Cross-Site Scripting (XSS)",
            "description": "Reflected XSS found in search parameter",
            "severity": "HIGH",
            "vuln_type": "xss",
            "evidence": "Payload: <script>alert(1)</script>",
            "discovery_date": "2025-01-15T15:10:00Z",
            "is_fixed": false,
            "source": "zap",
            "confidence": "high",
            "cvss_score": 6.5
        },
        ...
    ]
}
```

#### Get Vulnerability Details

```
GET /vulnerability/{vuln_id}/
```

Response:
```json
{
    "id": 456,
    "target": "example.com",
    "name": "Cross-Site Scripting (XSS)",
    "description": "Reflected XSS found in search parameter",
    "severity": "HIGH",
    "vuln_type": "xss",
    "evidence": "Payload: <script>alert(1)</script>",
    "discovery_date": "2025-01-15T15:10:00Z",
    "is_fixed": false,
    "fix_date": null,
    "source": "zap",
    "confidence": "high",
    "cvss_score": 6.5,
    "solution": "Implement proper input validation and output encoding",
    "references": ["https://owasp.org/www-community/attacks/xss/"],
    "cwe": "CWE-79",
    "metadata": {
        "url": "https://example.com/search?q=test",
        "parameter": "q"
    },
    "exploit_matches": [
        {
            "id": 789,
            "exploit_id": "12345",
            "title": "Example.com XSS Exploit",
            "confidence": 0.85,
            "status": "confirmed",
            "cve_id": "CVE-2023-1234"
        }
    ]
}
```

#### Start Vulnerability Scan

```
POST /vulnerability/scan/
Content-Type: application/json

{
    "target": "example.com",
    "scan_type": "standard",  // "quick", "standard", "full"
    "include_zap": true,
    "include_nuclei": true,
    "nuclei_scan_type": "basic",  // "basic", "advanced"
    "use_advanced_correlation": true
}
```

Response:
```json
{
    "id": 789,
    "status": "pending",
    "target": "example.com",
    "created_at": "2025-01-15T15:30:00Z"
}
```

#### Get Vulnerability Scan Status

```
GET /vulnerability/scan/{scan_id}/
```

Response:
```json
{
    "id": 789,
    "status": "completed",  // "pending", "in_progress", "completed", "failed" 
    "target": "example.com",
    "created_at": "2025-01-15T15:30:00Z",
    "completed_at": "2025-01-15T15:45:00Z",
    "results_summary": {
        "critical": 1,
        "high": 3,
        "medium": 5,
        "low": 9,
        "total": 18
    }
}
```

#### Mark Vulnerability as Fixed

```
PATCH /vulnerability/{vuln_id}/
Content-Type: application/json

{
    "is_fixed": true
}
```

Response:
```json
{
    "id": 456,
    "target": "example.com",
    "name": "Cross-Site Scripting (XSS)",
    "is_fixed": true,
    "fix_date": "2025-01-20T10:15:00Z"
}
```

### Exploit Manager API

#### List Exploits

```
GET /exploits/list/?search={search_term}
```

Parameters:
- `search` (optional): Search term for exploits
- `type` (optional): Filter by exploit type (webapps, remote, local)
- `platform` (optional): Filter by platform (Windows, Linux, etc.)

Response:
```json
{
    "count": 32,
    "next": "http://example.com/api/exploits/list/?search=xss&page=2",
    "previous": null,
    "results": [
        {
            "id": 101,
            "exploit_id": "12345",
            "title": "Example.com XSS Exploit",
            "description": "This exploit targets a reflected XSS vulnerability in Example.com",
            "type": "webapps",
            "platform": "Web",
            "date_published": "2024-10-15",
            "source": "ExploitDB",
            "cve_id": "CVE-2023-1234"
        },
        ...
    ]
}
```

#### Get Exploit Details

```
GET /exploits/{exploit_id}/
```

Response:
```json
{
    "id": 101,
    "exploit_id": "12345",
    "title": "Example.com XSS Exploit",
    "description": "This exploit targets a reflected XSS vulnerability in Example.com",
    "type": "webapps",
    "platform": "Web",
    "vulnerability_name": "Cross-Site Scripting",
    "cve_id": "CVE-2023-1234",
    "date_published": "2024-10-15",
    "date_added": "2025-01-10T09:30:00Z",
    "source": "ExploitDB",
    "source_url": "https://www.exploit-db.com/exploits/12345",
    "code": "# Exploit code here...",
    "author": "Security Researcher",
    "verified": true,
    "score": 8.5,
    "matches": [
        {
            "vulnerability_id": 456,
            "vulnerability_name": "Cross-Site Scripting (XSS)",
            "target": "example.com",
            "confidence_score": 0.85
        }
    ]
}
```

#### Match Vulnerabilities with Exploits

```
POST /exploits/match/
Content-Type: application/json

{
    "vulnerability_id": 456
}
```

Response:
```json
{
    "vulnerability_id": 456,
    "vulnerability_name": "Cross-Site Scripting (XSS)",
    "matches": [
        {
            "id": 789,
            "exploit_id": "12345",
            "title": "Example.com XSS Exploit",
            "confidence": 0.85,
            "match_reason": "Keywords and vulnerability type match",
            "cve_id": "CVE-2023-1234"
        },
        ...
    ]
}
```

### Automation API

#### List Workflows

```
GET /automation/workflows/
```

Parameters:
- `status` (optional): Filter by status (pending, scheduled, in_progress, completed, failed, canceled)
- `target` (optional): Filter by target

Response:
```json
{
    "count": 5,
    "next": null,
    "previous": null,
    "results": [
        {
            "id": 201,
            "name": "Scan example.com - 2025-01-15",
            "target": "example.com",
            "scan_profile": "standard",
            "status": "completed",
            "created_at": "2025-01-15T16:00:00Z",
            "scheduled_time": null,
            "start_time": "2025-01-15T16:00:10Z",
            "end_time": "2025-01-15T16:30:00Z"
        },
        ...
    ]
}
```

#### Create New Workflow

```
POST /automation/workflows/
Content-Type: application/json

{
    "name": "Scan example.com",
    "target": "example.com",
    "scan_profile": "standard",  // "quick", "standard", "full"
    "scheduled_time": "2025-01-20T10:00:00Z",  // Optional, null for immediate start
    "notification_email": "user@example.com"   // Optional
}
```

Response:
```json
{
    "id": 202,
    "name": "Scan example.com",
    "target": "example.com",
    "scan_profile": "standard",
    "status": "scheduled",
    "created_at": "2025-01-15T16:45:00Z",
    "scheduled_time": "2025-01-20T10:00:00Z"
}
```

#### Get Workflow Status

```
GET /automation/workflows/{workflow_id}/
```

Response:
```json
{
    "id": 202,
    "name": "Scan example.com",
    "target": "example.com",
    "scan_profile": "standard",
    "status": "scheduled",
    "created_at": "2025-01-15T16:45:00Z",
    "scheduled_time": "2025-01-20T10:00:00Z",
    "start_time": null,
    "end_time": null,
    "progress": 0,
    "tasks": [
        {
            "id": 501,
            "name": "Subdomain Enumeration - example.com",
            "type": "subdomain_enumeration",
            "status": "pending",
            "start_time": null,
            "end_time": null
        },
        ...
    ]
}
```

#### Cancel Workflow

```
POST /automation/workflows/{workflow_id}/cancel/
```

Response:
```json
{
    "id": 202,
    "status": "canceled",
    "message": "Workflow successfully canceled"
}
```

#### Create Scheduled Task

```
POST /automation/scheduled-tasks/
Content-Type: application/json

{
    "name": "Weekly scan of example.com",
    "target": "example.com",
    "scan_profile": "standard",
    "frequency": "weekly",  // "daily", "weekly", "monthly", "custom"
    "cron_expression": null,  // Required if frequency is "custom"
    "start_date": "2025-01-20",
    "end_date": "2025-12-31",  // Optional
    "notification_email": "user@example.com"
}
```

Response:
```json
{
    "id": 301,
    "name": "Weekly scan of example.com",
    "target": "example.com",
    "scan_profile": "standard",
    "frequency": "weekly",
    "cron_expression": null,
    "start_date": "2025-01-20",
    "end_date": "2025-12-31",
    "is_active": true,
    "created_at": "2025-01-15T17:00:00Z"
}
```

#### List Scheduled Tasks

```
GET /automation/scheduled-tasks/
```

Response:
```json
{
    "count": 3,
    "next": null,
    "previous": null,
    "results": [
        {
            "id": 301,
            "name": "Weekly scan of example.com",
            "target": "example.com",
            "scan_profile": "standard",
            "frequency": "weekly",
            "start_date": "2025-01-20",
            "end_date": "2025-12-31",
            "is_active": true,
            "last_execution": "2025-01-27T10:00:00Z",
            "last_status": "completed"
        },
        ...
    ]
}
```

### Reporting API

#### Generate Report

```
POST /reporting/generate/
Content-Type: application/json

{
    "target": "example.com",
    "report_type": "detailed",  // "basic", "detailed", "executive"
    "output_format": "pdf",     // "html", "pdf", "json"
    "workflow_id": 202          // Optional
}
```

Response:
```json
{
    "id": 401,
    "title": "Detailed Security Report - example.com",
    "creation_date": "2025-01-15T17:30:00Z",
    "report_type": "detailed_pdf",
    "download_url": "/api/reporting/download/401/"
}
```

#### List Reports

```
GET /reporting/list/
```

Parameters:
- `target` (optional): Filter by target
- `report_type` (optional): Filter by report type

Response:
```json
{
    "count": 8,
    "next": null,
    "previous": null,
    "results": [
        {
            "id": 401,
            "title": "Detailed Security Report - example.com",
            "creation_date": "2025-01-15T17:30:00Z",
            "report_type": "detailed_pdf",
            "download_url": "/api/reporting/download/401/"
        },
        ...
    ]
}
```

#### Download Report

```
GET /reporting/download/{report_id}/
```

Response: Binary file download (PDF, HTML, or JSON file)

### Network Visualization API

#### Get Network Map Data

```
GET /network/topology/{domain}/
```

Response:
```json
{
    "nodes": [
        {
            "id": "example.com",
            "name": "example.com",
            "node_type": "host",
            "ip_address": "192.168.1.1",
            "metadata": {
                "is_primary": true
            }
        },
        {
            "id": "admin.example.com",
            "name": "admin.example.com",
            "node_type": "subdomain",
            "ip_address": "192.168.1.2",
            "metadata": {}
        },
        {
            "id": "example.com:80",
            "name": "HTTP (80)",
            "node_type": "service",
            "metadata": {
                "service": "http",
                "banner": "nginx/1.18.0"
            }
        },
        ...
    ],
    "connections": [
        {
            "source": "example.com",
            "target": "admin.example.com",
            "connection_type": "subdomain"
        },
        {
            "source": "example.com",
            "target": "example.com:80",
            "connection_type": "service"
        },
        ...
    ]
}
```

### Error Handling

All API endpoints follow a consistent error response format:

```json
{
    "error": true,
    "code": "ERROR_CODE",
    "message": "Human-readable error message",
    "details": {
        // Additional error details if available
    }
}
```

Common error codes:
- `AUTHENTICATION_ERROR`: Invalid or missing authentication
- `PERMISSION_DENIED`: Insufficient permissions
- `VALIDATION_ERROR`: Invalid input data
- `RESOURCE_NOT_FOUND`: Requested resource does not exist
- `SCAN_ERROR`: Error during scan execution
- `RATE_LIMITED`: Too many requests

### Rate Limiting

API endpoints are rate-limited to prevent abuse. Current limits:
- Authentication endpoints: 5 requests per minute
- General endpoints: 60 requests per minute
- Scan-triggering endpoints: 10 requests per hour

The API includes rate limit headers in all responses:
```
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 58
X-RateLimit-Reset: 1642248245
```

### Pagination

List endpoints support pagination with the following query parameters:
- `page`: Page number (default: 1)
- `page_size`: Number of results per page (default: 20, max: 100)

Paginated responses include the following fields:
- `count`: Total number of results
- `next`: URL for the next page (null if on last page)
- `previous`: URL for the previous page (null if on first page)
- `results`: Array of results for the current page

### Filtering

Many endpoints support filtering by specific fields using query parameters. Common filters include:
- `target`: Filter by target domain/URL
- `status`: Filter by status (e.g., completed, pending, failed)
- `severity`: Filter by severity (CRITICAL, HIGH, MEDIUM, LOW)
- `created_after`/`created_before`: Filter by creation date range

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

Please read our [contributing guidelines](CONTRIBUTING.md) for details.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- OWASP ZAP team for their excellent web application scanner
- Nuclei project for template-based vulnerability scanning
- ExploitDB for vulnerability and exploit database
- Django project and community
- All open-source security tools that inspired this platform

---

## Contact and Support

For questions, suggestions, or issues, please:
- Open an issue on GitHub
- Contact the maintenance team at [harmeek1929@gmail.com]

---

**Disclaimer**: This tool is designed for security professionals conducting authorized security assessments. Misuse of this tool against systems without proper permission may violate laws and regulations. The developers are not responsible for any misuse or damage caused by this tool.
