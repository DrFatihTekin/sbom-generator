import json
import datetime
from typing import Dict, Any, List

class HTMLGenerator:
    """Generator for a premium, interactive, self-contained HTML SBOM dashboard."""

    def __init__(self, project_name: str, project_version: str = "1.0.0"):
        self.project_name = project_name
        self.project_version = project_version

    def generate(self, files: List[Dict[str, Any]], dependencies: List[Dict[str, Any]], spdx_data: Dict[str, Any], cyclonedx_data: Dict[str, Any], spdx3_data: Dict[str, Any] = None) -> str:
        """Generate the HTML report as a string."""
        
        # Serialize SBOMs to embedded scripts for easy download
        spdx_json = json.dumps(spdx_data, indent=2)
        spdx3_json = json.dumps(spdx3_data, indent=2) if spdx3_data else "null"
        cyclonedx_json = json.dumps(cyclonedx_data, indent=2)
        
        # Create stats for rendering
        total_files = len(files)
        total_deps = len(dependencies)
        
        # Calculate distinct licenses
        licenses = set()
        for f in files:
            if f.get("license") and f["license"] != "NOASSERTION":
                licenses.add(f["license"])
        for d in dependencies:
            if d.get("license") and d["license"] != "NOASSERTION":
                licenses.add(d["license"])
        total_licenses = len(licenses)

        # Calculate project size
        total_size = sum(f.get("size", 0) for f in files)
        
        # Format size readable
        if total_size > 1024*1024*1024:
            size_str = f"{total_size / (1024*1024*1024):.2f} GB"
        elif total_size > 1024*1024:
            size_str = f"{total_size / (1024*1024):.2f} MB"
        else:
            size_str = f"{total_size / 1024:.2f} KB"

        # Embedded HTML/CSS/JS Template
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{self.project_name} SBOM Dashboard</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg-primary: #0a0e17;
            --bg-secondary: #121824;
            --bg-card: rgba(30, 41, 59, 0.5);
            --bg-card-hover: rgba(30, 41, 59, 0.8);
            --border-color: rgba(255, 255, 255, 0.08);
            --border-glow: rgba(59, 130, 246, 0.2);
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --text-muted: #64748b;
            --primary: #3b82f6;
            --primary-glow: rgba(59, 130, 246, 0.15);
            --secondary: #8b5cf6;
            --success: #10b981;
            --warning: #f59e0b;
            --danger: #ef4444;
            --sidebar-width: 260px;
        }}

        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}

        body {{
            font-family: 'Inter', sans-serif;
            background-color: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
            display: flex;
            overflow: hidden;
        }}

        /* Scrollbar styling */
        ::-webkit-scrollbar {{
            width: 8px;
            height: 8px;
        }}
        ::-webkit-scrollbar-track {{
            background: var(--bg-primary);
        }}
        ::-webkit-scrollbar-thumb {{
            background: var(--bg-card);
            border-radius: 4px;
        }}
        ::-webkit-scrollbar-thumb:hover {{
            background: var(--text-muted);
        }}

        /* Sidebar styling */
        aside {{
            width: var(--sidebar-width);
            background-color: var(--bg-secondary);
            border-right: 1px solid var(--border-color);
            display: flex;
            flex-direction: column;
            padding: 24px;
            z-index: 10;
        }}

        .logo-container {{
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 36px;
        }}

        .logo-icon {{
            width: 36px;
            height: 36px;
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 800;
            font-size: 18px;
            color: white;
            box-shadow: 0 0 15px var(--primary-glow);
        }}

        .logo-text h1 {{
            font-size: 18px;
            font-weight: 700;
            letter-spacing: -0.5px;
        }}

        .logo-text p {{
            font-size: 11px;
            color: var(--text-muted);
            font-weight: 500;
        }}

        nav {{
            display: flex;
            flex-direction: column;
            gap: 8px;
            flex-grow: 1;
        }}

        .nav-item {{
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 12px 16px;
            border-radius: 8px;
            color: var(--text-secondary);
            text-decoration: none;
            font-weight: 500;
            font-size: 14px;
            transition: all 0.2s ease;
            cursor: pointer;
            border: 1px solid transparent;
        }}

        .nav-item:hover {{
            color: var(--text-primary);
            background-color: var(--bg-card);
        }}

        .nav-item.active {{
            color: var(--text-primary);
            background: linear-gradient(90deg, var(--primary-glow), transparent);
            border-color: rgba(59, 130, 246, 0.3);
            box-shadow: inset 3px 0 0 var(--primary);
        }}

        .nav-icon {{
            width: 18px;
            height: 18px;
            stroke-width: 2px;
            stroke: currentColor;
            fill: none;
        }}

        .sidebar-footer {{
            margin-top: auto;
            border-top: 1px solid var(--border-color);
            padding-top: 16px;
        }}

        .export-btn-group {{
            display: flex;
            flex-direction: column;
            gap: 8px;
        }}

        .btn {{
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            padding: 10px;
            border-radius: 6px;
            font-size: 12px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s ease;
            border: 1px solid var(--border-color);
            background-color: var(--bg-card);
            color: var(--text-primary);
            text-align: center;
            text-decoration: none;
        }}

        .btn:hover {{
            background-color: var(--bg-card-hover);
            border-color: var(--primary);
            box-shadow: 0 0 10px rgba(59, 130, 246, 0.15);
        }}

        .btn-primary {{
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            border: none;
        }}

        .btn-primary:hover {{
            opacity: 0.9;
        }}

        /* Main Content container */
        main {{
            flex-grow: 1;
            display: flex;
            flex-direction: column;
            overflow: hidden;
            background: radial-gradient(circle at 70% 10%, rgba(59, 130, 246, 0.03), transparent 60%);
        }}

        header {{
            height: 70px;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 0 40px;
            background-color: rgba(10, 14, 23, 0.5);
            backdrop-filter: blur(12px);
        }}

        .header-title h2 {{
            font-size: 20px;
            font-weight: 700;
            letter-spacing: -0.5px;
        }}

        .header-meta {{
            display: flex;
            gap: 16px;
            font-size: 12px;
            color: var(--text-muted);
        }}

        .meta-badge {{
            background-color: var(--bg-card);
            border: 1px solid var(--border-color);
            padding: 4px 8px;
            border-radius: 4px;
            color: var(--text-secondary);
        }}

        /* Content panels */
        .content-panel {{
            display: none;
            flex-grow: 1;
            padding: 40px;
            overflow-y: auto;
        }}

        .content-panel.active {{
            display: flex;
            flex-direction: column;
            gap: 24px;
        }}

        /* Stats grid */
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 20px;
        }}

        .stat-card {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 24px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }}

        .stat-card::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 3px;
            background: transparent;
            transition: all 0.3s ease;
        }}

        .stat-card:hover {{
            background: var(--bg-card-hover);
            transform: translateY(-2px);
            border-color: var(--border-glow);
            box-shadow: 0 10px 20px rgba(0, 0, 0, 0.2);
        }}

        .stat-card:hover::before {{
            background: linear-gradient(90deg, var(--primary), var(--secondary));
        }}

        .stat-info h3 {{
            font-size: 13px;
            color: var(--text-secondary);
            font-weight: 500;
            margin-bottom: 8px;
        }}

        .stat-value {{
            font-size: 28px;
            font-weight: 700;
            letter-spacing: -0.5px;
        }}

        .stat-icon-container {{
            width: 48px;
            height: 48px;
            border-radius: 10px;
            background-color: rgba(255, 255, 255, 0.03);
            display: flex;
            align-items: center;
            justify-content: center;
            color: var(--primary);
        }}

        /* Two columns layout */
        .dashboard-row {{
            display: grid;
            grid-template-columns: 1.5fr 1fr;
            gap: 24px;
        }}

        .card {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 24px;
            display: flex;
            flex-direction: column;
            gap: 16px;
        }}

        .card-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}

        .card-title {{
            font-size: 15px;
            font-weight: 600;
            color: var(--text-primary);
        }}

        /* Interactive Tables */
        .table-controls {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 16px;
            flex-wrap: wrap;
        }}

        .search-wrapper {{
            position: relative;
            flex-grow: 1;
            max-width: 400px;
        }}

        .search-input {{
            width: 100%;
            background-color: var(--bg-card);
            border: 1px solid var(--border-color);
            padding: 10px 16px 10px 40px;
            border-radius: 8px;
            color: var(--text-primary);
            font-size: 14px;
            outline: none;
            transition: all 0.2s ease;
        }}

        .search-input:focus {{
            border-color: var(--primary);
            box-shadow: 0 0 10px var(--primary-glow);
        }}

        .search-icon {{
            position: absolute;
            left: 14px;
            top: 50%;
            transform: translateY(-50%);
            width: 16px;
            height: 16px;
            color: var(--text-muted);
            pointer-events: none;
        }}

        .filter-select {{
            background-color: var(--bg-card);
            border: 1px solid var(--border-color);
            padding: 10px 16px;
            border-radius: 8px;
            color: var(--text-primary);
            font-size: 14px;
            outline: none;
            cursor: pointer;
        }}

        .filter-select:focus {{
            border-color: var(--primary);
        }}

        .table-container {{
            width: 100%;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            overflow: hidden;
            background-color: rgba(10, 14, 23, 0.3);
        }}

        .sbom-table {{
            width: 100%;
            border-collapse: collapse;
            text-align: left;
            font-size: 14px;
        }}

        .sbom-table th {{
            background-color: rgba(255, 255, 255, 0.02);
            color: var(--text-secondary);
            font-weight: 600;
            padding: 14px 16px;
            border-bottom: 1px solid var(--border-color);
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}

        .sbom-table td {{
            padding: 14px 16px;
            border-bottom: 1px solid var(--border-color);
            color: var(--text-secondary);
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            max-width: 250px;
        }}

        .sbom-table tr:hover {{
            background-color: rgba(255, 255, 255, 0.015);
            cursor: pointer;
        }}

        .sbom-table tr.selected {{
            background-color: var(--primary-glow);
        }}

        .tag {{
            display: inline-flex;
            align-items: center;
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
        }}

        .tag-source {{ background-color: rgba(59, 130, 246, 0.15); color: #60a5fa; }}
        .tag-library {{ background-color: rgba(139, 92, 246, 0.15); color: #a78bfa; }}
        .tag-success {{ background-color: rgba(16, 185, 129, 0.15); color: #34d399; }}
        .tag-warning {{ background-color: rgba(245, 158, 11, 0.15); color: #fbbf24; }}
        .tag-danger {{ background-color: rgba(239, 68, 68, 0.15); color: #f87171; }}

        /* Split-screen detail view layout */
        .split-layout {{
            display: grid;
            grid-template-columns: 2fr 1.2fr;
            gap: 24px;
            align-items: start;
        }}

        /* Detail panel */
        .detail-panel {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 24px;
            display: flex;
            flex-direction: column;
            gap: 20px;
            position: sticky;
            top: 0;
            max-height: calc(100vh - 150px);
            overflow-y: auto;
        }}

        .detail-header {{
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 16px;
        }}

        .detail-header h3 {{
            font-size: 18px;
            font-weight: 700;
            margin-bottom: 6px;
            word-break: break-all;
        }}

        .detail-section-title {{
            font-size: 11px;
            text-transform: uppercase;
            color: var(--text-muted);
            letter-spacing: 1px;
            font-weight: 700;
            margin-top: 12px;
            margin-bottom: 8px;
        }}

        .detail-grid {{
            display: grid;
            grid-template-columns: 1fr;
            gap: 12px;
        }}

        .detail-item {{
            display: flex;
            flex-direction: column;
            gap: 4px;
        }}

        .detail-label {{
            font-size: 11px;
            color: var(--text-muted);
        }}

        .detail-value {{
            font-size: 13px;
            color: var(--text-primary);
            word-break: break-all;
        }}

        .code-block {{
            font-family: 'JetBrains Mono', monospace;
            background-color: rgba(10, 14, 23, 0.8);
            border: 1px solid var(--border-color);
            padding: 10px;
            border-radius: 6px;
            font-size: 12px;
            overflow-x: auto;
            color: #38bdf8;
            max-width: 100%;
        }}

        /* SVG Chart visualization */
        .donut-chart-container {{
            display: flex;
            align-items: center;
            gap: 24px;
            justify-content: center;
            padding: 10px 0;
        }}

        .chart-legend {{
            display: flex;
            flex-direction: column;
            gap: 10px;
            max-height: 220px;
            overflow-y: auto;
            padding-right: 10px;
        }}

        .legend-item {{
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 12px;
            color: var(--text-secondary);
        }}

        .legend-color {{
            width: 12px;
            height: 12px;
            border-radius: 3px;
            flex-shrink: 0;
        }}

        .bar-chart {{
            display: flex;
            flex-direction: column;
            gap: 12px;
            padding-top: 10px;
        }}

        .bar-row {{
            display: flex;
            align-items: center;
            gap: 12px;
            font-size: 12px;
        }}

        .bar-label {{
            width: 100px;
            text-overflow: ellipsis;
            white-space: nowrap;
            overflow: hidden;
            color: var(--text-secondary);
        }}

        .bar-container {{
            flex-grow: 1;
            height: 8px;
            background-color: rgba(255, 255, 255, 0.05);
            border-radius: 4px;
            overflow: hidden;
        }}

        .bar-fill {{
            height: 100%;
            background: linear-gradient(90deg, var(--primary), var(--secondary));
            border-radius: 4px;
            width: 0;
            transition: width 1s ease-out;
        }}

        .bar-val {{
            width: 30px;
            text-align: right;
            color: var(--text-primary);
            font-weight: 500;
        }}

        /* Empty state */
        .empty-state {{
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            padding: 40px;
            color: var(--text-muted);
            text-align: center;
            gap: 16px;
        }}

        .empty-icon {{
            width: 48px;
            height: 48px;
            stroke-width: 1.5px;
            stroke: currentColor;
            fill: none;
        }}

        /* Pagination style */
        .pagination {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-top: 16px;
            font-size: 13px;
            color: var(--text-secondary);
        }}

        .pagination-btn-group {{
            display: flex;
            gap: 8px;
        }}

        .page-btn {{
            padding: 6px 12px;
            border: 1px solid var(--border-color);
            background-color: var(--bg-card);
            color: var(--text-primary);
            border-radius: 4px;
            cursor: pointer;
            font-size: 12px;
        }}

        .page-btn:disabled {{
            opacity: 0.4;
            cursor: not-allowed;
        }}

        .page-btn:hover:not(:disabled) {{
            border-color: var(--primary);
        }}
    </style>
</head>
<body>

    <!-- Sidebar -->
    <aside>
        <div class="logo-container">
            <div class="logo-icon">S</div>
            <div class="logo-text">
                <h1>OpenSBOM</h1>
                <p>Extractor & Viewer</p>
            </div>
        </div>

        <nav>
            <div class="nav-item active" onclick="switchTab('dashboard', this)">
                <svg class="nav-icon" viewBox="0 0 24 24"><path d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6"/></svg>
                Dashboard
            </div>
            <div class="nav-item" onclick="switchTab('packages', this)">
                <svg class="nav-icon" viewBox="0 0 24 24"><path d="M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10M4 7v10l8 4"/></svg>
                Dependencies ({total_deps})
            </div>
            <div class="nav-item" onclick="switchTab('files', this)">
                <svg class="nav-icon" viewBox="0 0 24 24"><path d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>
                Source Files ({total_files})
            </div>
        </nav>

        <div class="sidebar-footer">
            <div class="export-btn-group">
                <a class="btn btn-primary" id="download-spdx-btn" href="#">
                    <svg class="nav-icon" style="width: 14px; height: 14px;" viewBox="0 0 24 24"><path d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/></svg>
                    Export SPDX 2.3 JSON
                </a>
                <a class="btn" id="download-spdx3-btn" href="#">
                    Export SPDX 3.0 JSON
                </a>
                <a class="btn" id="download-cyclonedx-btn" href="#">
                    Export CycloneDX
                </a>
            </div>
        </div>
    </aside>

    <!-- Main Workspace -->
    <main>
        <!-- Header -->
        <header>
            <div class="header-title">
                <h2>{self.project_name}</h2>
            </div>
            <div class="header-meta">
                <div class="meta-badge">Version: {self.project_version}</div>
                <div class="meta-badge">Scanned: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M")}</div>
            </div>
        </header>

        <!-- DASHBOARD PANEL -->
        <div id="dashboard-panel" class="content-panel active">
            <!-- Stats -->
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-info">
                        <h3>Total Scanned Files</h3>
                        <div class="stat-value">{total_files}</div>
                    </div>
                    <div class="stat-icon-container">
                        <svg class="nav-icon" viewBox="0 0 24 24"><path d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>
                    </div>
                </div>
                <div class="stat-card">
                    <div class="stat-info">
                        <h3>Third-Party Packages</h3>
                        <div class="stat-value">{total_deps}</div>
                    </div>
                    <div class="stat-icon-container" style="color: var(--secondary);">
                        <svg class="nav-icon" viewBox="0 0 24 24"><path d="M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10M4 7v10l8 4"/></svg>
                    </div>
                </div>
                <div class="stat-card">
                    <div class="stat-info">
                        <h3>Detected Licenses</h3>
                        <div class="stat-value">{total_licenses}</div>
                    </div>
                    <div class="stat-icon-container" style="color: var(--success);">
                        <svg class="nav-icon" viewBox="0 0 24 24"><path d="M9 12l2 2 4-4M7.835 4.697a3.42 3.42 0 001.946-.806 3.42 3.42 0 014.438 0 3.42 3.42 0 001.946.806 3.42 3.42 0 013.138 3.138 3.42 3.42 0 00.806 1.946 3.42 3.42 0 010 4.438 3.42 3.42 0 00-.806 1.946 3.42 3.42 0 01-3.138 3.138 3.42 3.42 0 00-1.946.806 3.42 3.42 0 01-4.438 0 3.42 3.42 0 00-1.946-.806 3.42 3.42 0 01-3.138-3.138 3.42 3.42 0 00-.806-1.946 3.42 3.42 0 010-4.438 3.42 3.42 0 00.806-1.946 3.42 3.42 0 013.138-3.138z"/></svg>
                    </div>
                </div>
                <div class="stat-card">
                    <div class="stat-info">
                        <h3>Total Project Size</h3>
                        <div class="stat-value">{size_str}</div>
                    </div>
                    <div class="stat-icon-container" style="color: var(--warning);">
                        <svg class="nav-icon" viewBox="0 0 24 24"><path d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z"/></svg>
                    </div>
                </div>
            </div>

            <!-- Visual Charts Row -->
            <div class="dashboard-row">
                <!-- License Distribution Chart -->
                <div class="card">
                    <div class="card-header">
                        <div class="card-title">License Distribution (Top 10)</div>
                    </div>
                    <div class="donut-chart-container">
                        <svg id="donut-svg" width="160" height="160" viewBox="0 0 42 42" style="transform: rotate(-90deg); border-radius: 50%;"></svg>
                        <div class="chart-legend" id="donut-legend"></div>
                    </div>
                </div>

                <!-- Package Type Distribution Chart -->
                <div class="card">
                    <div class="card-header">
                        <div class="card-title">Components by Type</div>
                    </div>
                    <div class="bar-chart" id="type-bar-chart"></div>
                </div>
            </div>

            <!-- General Metadata Card -->
            <div class="card">
                <div class="card-header">
                    <div class="card-title">SBOM Extraction Properties</div>
                </div>
                <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 16px; font-size: 13px;">
                    <div><strong>Project Name:</strong> {self.project_name}</div>
                    <div><strong>Project Version:</strong> {self.project_version}</div>
                    <div><strong>SPDX Standard:</strong> SPDX 2.3 (JSON)</div>
                    <div><strong>CycloneDX Standard:</strong> CycloneDX 1.5 (JSON)</div>
                    <div><strong>SPDX Namespace:</strong> <code style="word-break: break-all; color: var(--primary);">{spdx_data.get('documentNamespace', '')}</code></div>
                    <div><strong>CycloneDX URN:</strong> <code style="word-break: break-all; color: var(--secondary);">{cyclonedx_data.get('serialNumber', '')}</code></div>
                </div>
            </div>
        </div>

        <!-- DEPENDENCIES PANEL -->
        <div id="packages-panel" class="content-panel">
            <div class="table-controls">
                <div class="search-wrapper">
                    <svg class="search-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/></svg>
                    <input type="text" id="packages-search" class="search-input" placeholder="Search dependencies..." oninput="filterPackages()">
                </div>
                <select id="packages-filter-type" class="filter-select" onchange="filterPackages()">
                    <option value="all">All Ecosystems</option>
                    <option value="pip">pip (Python)</option>
                    <option value="npm">npm (NodeJS)</option>
                    <option value="cargo">cargo (Rust)</option>
                    <option value="go">go (Golang)</option>
                </select>
            </div>

            <div class="split-layout">
                <div>
                    <div class="table-container">
                        <table class="sbom-table">
                            <thead>
                                <tr>
                                    <th>Package Name</th>
                                    <th>Version</th>
                                    <th>Type</th>
                                    <th>License</th>
                                </tr>
                            </thead>
                            <tbody id="packages-table-body"></tbody>
                        </table>
                        <div id="packages-empty" class="empty-state" style="display: none;">
                            <svg class="empty-icon" viewBox="0 0 24 24"><path d="M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10M4 7v10l8 4"/></svg>
                            <p>No package dependencies found matching the filters.</p>
                        </div>
                    </div>
                </div>
                <!-- Package Details -->
                <div class="detail-panel" id="package-detail-panel">
                    <div class="empty-state" id="package-detail-empty">
                        <svg class="empty-icon" viewBox="0 0 24 24"><path d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
                        <p>Select a package dependency to view complete SBOM details.</p>
                    </div>
                    <div id="package-detail-content" style="display: none;">
                        <div class="detail-header">
                            <h3 id="p-detail-name">package-name</h3>
                            <span class="tag tag-library" id="p-detail-tag">npm</span>
                        </div>
                        <div class="detail-grid">
                            <div class="detail-item">
                                <div class="detail-label">Version</div>
                                <div class="detail-value" id="p-detail-version">1.0.0</div>
                            </div>
                            <div class="detail-item">
                                <div class="detail-label">License Declared</div>
                                <div class="detail-value" id="p-detail-license">MIT</div>
                            </div>
                            <div class="detail-item">
                                <div class="detail-label">PURL (Package URL)</div>
                                <div class="code-block" id="p-detail-purl">pkg:npm/package-name@1.0.0</div>
                            </div>
                            <div class="detail-item">
                                <div class="detail-label">Manifest File Location</div>
                                <div class="detail-value" id="p-detail-manifest">package.json</div>
                            </div>
                            <div class="detail-item">
                                <div class="detail-label">SPDX ID Reference</div>
                                <div class="detail-value" id="p-detail-spdxref">SPDXRef-Package-package-name-1-0-0</div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- SOURCE FILES PANEL -->
        <div id="files-panel" class="content-panel">
            <div class="table-controls">
                <div class="search-wrapper">
                    <svg class="search-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/></svg>
                    <input type="text" id="files-search" class="search-input" placeholder="Search source files..." oninput="filterFiles(1)">
                </div>
                <select id="files-filter-license" class="filter-select" onchange="filterFiles(1)">
                    <option value="all">All Licenses</option>
                </select>
            </div>

            <div class="split-layout">
                <div>
                    <div class="table-container">
                        <table class="sbom-table">
                            <thead>
                                <tr>
                                    <th>File Path</th>
                                    <th>Size</th>
                                    <th>License</th>
                                </tr>
                            </thead>
                            <tbody id="files-table-body"></tbody>
                        </table>
                        <div id="files-empty" class="empty-state" style="display: none;">
                            <svg class="empty-icon" viewBox="0 0 24 24"><path d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>
                            <p>No source files found matching the filters.</p>
                        </div>
                    </div>
                    <!-- Pagination -->
                    <div class="pagination">
                        <span id="pagination-info">Showing 0-0 of 0 files</span>
                        <div class="pagination-btn-group">
                            <button id="prev-page-btn" class="page-btn" onclick="prevPage()">Prev</button>
                            <button id="next-page-btn" class="page-btn" onclick="nextPage()">Next</button>
                        </div>
                    </div>
                </div>
                <!-- File Details -->
                <div class="detail-panel" id="file-detail-panel">
                    <div class="empty-state" id="file-detail-empty">
                        <svg class="empty-icon" viewBox="0 0 24 24"><path d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
                        <p>Select a file to view licensing and hashes metadata.</p>
                    </div>
                    <div id="file-detail-content" style="display: none;">
                        <div class="detail-header">
                            <h3 id="f-detail-name">file.c</h3>
                            <span class="tag tag-source" id="f-detail-tag">Source</span>
                        </div>
                        <div class="detail-grid">
                            <div class="detail-item">
                                <div class="detail-label">Relative Path</div>
                                <div class="detail-value" id="f-detail-path">src/file.c</div>
                            </div>
                            <div class="detail-item">
                                <div class="detail-label">File Size</div>
                                <div class="detail-value" id="f-detail-size">0 bytes</div>
                            </div>
                            <div class="detail-item">
                                <div class="detail-label">SPDX License Identifier</div>
                                <div class="detail-value" id="f-detail-license">GPL-2.0-only</div>
                            </div>
                            <div class="detail-item">
                                <div class="detail-label">SHA-256 Hash</div>
                                <div class="code-block" id="f-detail-sha256">-</div>
                            </div>
                            <div class="detail-item">
                                <div class="detail-label">SHA-1 Hash</div>
                                <div class="code-block" id="f-detail-sha1">-</div>
                            </div>
                            <div class="detail-item">
                                <div class="detail-label">SPDX ID Reference</div>
                                <div class="detail-value" id="f-detail-spdxref">SPDXRef-File-abcd</div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </main>

    <!-- Embedded SBOM data -->
    <script id="spdx-json-data" type="application/json">{spdx_json}</script>
    <script id="spdx3-json-data" type="application/json">{spdx3_json}</script>
    <script id="cyclonedx-json-data" type="application/json">{cyclonedx_json}</script>
    
    <script>
        // Load data embedded in scripts
        const spdxData = JSON.parse(document.getElementById('spdx-json-data').textContent);
        const spdx3Data = JSON.parse(document.getElementById('spdx3-json-data').textContent);
        const cyclonedxData = JSON.parse(document.getElementById('cyclonedx-json-data').textContent);

        // State variables
        let filesList = [];
        let packagesList = [];
        let activeTab = 'dashboard';
        
        // Pagination state for files
        const itemsPerPage = 25;
        let currentFilesPage = 1;
        let filteredFiles = [];
        let selectedFileId = null;
        let selectedPackageId = null;

        // Colors for licenses and charts
        const chartColors = [
            '#3b82f6', '#8b5cf6', '#10b981', '#f59e0b', '#ef4444', 
            '#ec4899', '#06b6d4', '#14b8a6', '#f43f5e', '#84cc16'
        ];

        // On Load initialization
        window.onload = function() {{
            parseData();
            setupExportLinks();
            renderDashboard();
            renderPackagesTable();
            renderFilesTable();
            populateLicenseFilter();
        }};

        // Set up the browser download links for SPDX and CycloneDX files
        function setupExportLinks() {{
            const spdxBlob = new Blob([JSON.stringify(spdxData, null, 2)], {{type: "application/json"}});
            document.getElementById('download-spdx-btn').href = URL.createObjectURL(spdxBlob);
            document.getElementById('download-spdx-btn').download = `${{spdxData.name || 'project'}}-sbom.spdx.json`;

            if (spdx3Data) {{
                const spdx3Blob = new Blob([JSON.stringify(spdx3Data, null, 2)], {{type: "application/json"}});
                document.getElementById('download-spdx3-btn').href = URL.createObjectURL(spdx3Blob);
                document.getElementById('download-spdx3-btn').download = `${{spdxData.name || 'project'}}-sbom.spdx3.json`;
            }} else {{
                const btn = document.getElementById('download-spdx3-btn');
                if (btn) btn.style.display = 'none';
            }}

            const cdBlob = new Blob([JSON.stringify(cyclonedxData, null, 2)], {{type: "application/json"}});
            document.getElementById('download-cyclonedx-btn').href = URL.createObjectURL(cdBlob);
            document.getElementById('download-cyclonedx-btn').download = `${{spdxData.name || 'project'}}-sbom.cdx.json`;
        }}

        // Parse data from JSON structures
        function parseData() {{
            // Parse Files from SPDX
            if (spdxData.files) {{
                filesList = spdxData.files.map(f => {{
                    const sha256Obj = f.checksums ? f.checksums.find(c => c.algorithm === 'SHA256') : null;
                    const sha1Obj = f.checksums ? f.checksums.find(c => c.algorithm === 'SHA1') : null;
                    
                    // Simple size lookup if available (approximate or parsed)
                    // We try to find match from file info or default to 0
                    return {{
                        spdxId: f.SPDXID,
                        name: f.fileName.replace(/^\\.\\//, ''),
                        path: f.fileName.replace(/^\\.\\//, ''),
                        license: f.licenseConcluded || 'NOASSERTION',
                        sha256: sha256Obj ? sha256Obj.checksumValue : '',
                        sha1: sha1Obj ? sha1Obj.checksumValue : '',
                        is_source: f.fileTypes && f.fileTypes.includes('SOURCE'),
                        size: 0 // Will display as N/A or set if scanner outputs it
                    }};
                }});
            }}
            
            // Parse Dependencies from SPDX
            if (spdxData.packages) {{
                // Skip the main package which represents the project itself
                packagesList = spdxData.packages
                    .filter(p => p.SPDXID !== 'SPDXRef-Package-Main')
                    .map(p => {{
                        const purlRef = p.externalRefs ? p.externalRefs.find(r => r.referenceType === 'purl') : null;
                        const purl = purlRef ? purlRef.referenceLocator : '';
                        
                        let type = 'pip';
                        if (purl) {{
                            const match = purl.match(/^pkg:([^/]+)/);
                            if (match) type = match[1];
                        }}
                        
                        return {{
                            spdxId: p.SPDXID,
                            name: p.name,
                            version: p.versionInfo || 'unknown',
                            license: p.licenseDeclared || 'NOASSERTION',
                            type: type,
                            purl: purl,
                            manifest: type === 'pip' ? 'requirements.txt' : (type.startsWith('npm') ? 'package.json' : (type === 'cargo' ? 'Cargo.toml' : 'go.mod'))
                        }};
                    }});
            }}
            
            filteredFiles = [...filesList];
        }}

        // Switch panels
        function switchTab(tabName, element) {{
            activeTab = tabName;
            
            // Remove active classes
            document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
            document.querySelectorAll('.content-panel').forEach(el => el.classList.remove('active'));
            
            // Add active classes
            element.classList.add('active');
            document.getElementById(`${{tabName}}-panel`).classList.add('active');
        }}

        // Render Dashboard Charts
        function renderDashboard() {{
            // 1. License count
            const licCounts = {{}};
            filesList.forEach(f => {{
                if (f.license !== 'NOASSERTION') {{
                    licCounts[f.license] = (licCounts[f.license] || 0) + 1;
                }}
            }});
            packagesList.forEach(p => {{
                if (p.license !== 'NOASSERTION') {{
                    licCounts[p.license] = (licCounts[p.license] || 0) + 1;
                }}
            }});

            const sortedLics = Object.entries(licCounts)
                .sort((a, b) => b[1] - a[1])
                .slice(0, 10);
            
            renderDonutChart(sortedLics);

            // 2. Types/Ecosystems bar chart
            const typeCounts = {{}};
            packagesList.forEach(p => {{
                typeCounts[p.type] = (typeCounts[p.type] || 0) + 1;
            }});
            if (filesList.length > 0) {{
                typeCounts['source code'] = filesList.length;
            }}

            renderBarChart(typeCounts);
        }}

        // Draw SVG Donut Chart
        function renderDonutChart(data) {{
            const svg = document.getElementById('donut-svg');
            const legend = document.getElementById('donut-legend');
            svg.innerHTML = '';
            legend.innerHTML = '';
            
            if (data.length === 0) {{
                svg.innerHTML = '<circle cx="21" cy="21" r="15.915" fill="none" stroke="rgba(255,255,255,0.05)" stroke-width="6"/>';
                legend.innerHTML = '<div class="legend-item"><span class="legend-color" style="background:#64748b;"></span>No License Data</div>';
                return;
            }}

            const total = data.reduce((sum, item) => sum + item[1], 0);
            let offset = 0;

            data.forEach(([license, count], index) => {{
                const percentage = (count / total) * 100;
                const strokeDash = `${{percentage}} ${{100 - percentage}}`;
                const color = chartColors[index % chartColors.length];
                
                // SVG Circle path for donut segment
                const circle = document.createElementNS("http://www.w3.org/2000/svg", "circle");
                circle.setAttribute("cx", "21");
                circle.setAttribute("cy", "21");
                circle.setAttribute("r", "15.91549430918954"); // Math logic to make circumference exactly 100
                circle.setAttribute("fill", "none");
                circle.setAttribute("stroke", color);
                circle.setAttribute("stroke-width", "6");
                circle.setAttribute("stroke-dasharray", strokeDash);
                circle.setAttribute("stroke-dashoffset", 100 - offset);
                
                svg.appendChild(circle);
                offset += percentage;

                // Legend item
                const legendItem = document.createElement('div');
                legendItem.className = 'legend-item';
                legendItem.innerHTML = `
                    <span class="legend-color" style="background:${{color}};"></span>
                    <span>${{license}} (${{count}} - ${{percentage.toFixed(1)}}%)</span>
                `;
                legend.appendChild(legendItem);
            }});
            
            // Add a center hole to make it look like a donut
            const center = document.createElementNS("http://www.w3.org/2000/svg", "circle");
            center.setAttribute("cx", "21");
            center.setAttribute("cy", "21");
            center.setAttribute("r", "12");
            center.setAttribute("fill", "var(--bg-primary)");
            svg.appendChild(center);
        }}

        // Draw SVG/CSS Bar Chart
        function renderBarChart(typeCounts) {{
            const container = document.getElementById('type-bar-chart');
            container.innerHTML = '';

            const sortedTypes = Object.entries(typeCounts).sort((a, b) => b[1] - a[1]);
            const maxVal = sortedTypes.length > 0 ? sortedTypes[0][1] : 1;

            sortedTypes.forEach(([type, count]) => {{
                const pct = (count / maxVal) * 100;
                const row = document.createElement('div');
                row.className = 'bar-row';
                row.innerHTML = `
                    <div class="bar-label" title="${{type}}">${{type.toUpperCase()}}</div>
                    <div class="bar-container">
                        <div class="bar-fill" style="width: ${{pct}}%;"></div>
                    </div>
                    <div class="bar-val">${{count}}</div>
                `;
                container.appendChild(row);
            }});
        }}

        // Populate license drop-down filter
        function populateLicenseFilter() {{
            const select = document.getElementById('files-filter-license');
            const licenses = new Set();
            filesList.forEach(f => {{
                if (f.license && f.license !== 'NOASSERTION') {{
                    licenses.add(f.license);
                }}
            }});
            
            [...licenses].sort().forEach(lic => {{
                const opt = document.createElement('option');
                opt.value = lic;
                opt.textContent = lic;
                select.appendChild(opt);
            }});
        }}

        // Render Packages Table
        function renderPackagesTable(filteredPackages = null) {{
            const tbody = document.getElementById('packages-table-body');
            const empty = document.getElementById('packages-empty');
            tbody.innerHTML = '';
            
            const pkgs = filteredPackages || packagesList;
            
            if (pkgs.length === 0) {{
                empty.style.display = 'flex';
                return;
            }}
            
            empty.style.display = 'none';
            pkgs.forEach(pkg => {{
                const tr = document.createElement('tr');
                if (selectedPackageId === pkg.spdxId) tr.className = 'selected';
                
                tr.onclick = () => selectPackage(pkg);
                tr.innerHTML = `
                    <td><strong>${{pkg.name}}</strong></td>
                    <td>${{pkg.version}}</td>
                    <td><span class="tag tag-library">${{pkg.type}}</span></td>
                    <td><span class="tag ${{pkg.license !== 'NOASSERTION' ? 'tag-success' : 'tag-danger'}}">${{pkg.license}}</span></td>
                `;
                tbody.appendChild(tr);
            }});
        }}

        // Filter packages based on search / type selector
        function filterPackages() {{
            const query = document.getElementById('packages-search').value.toLowerCase();
            const typeFilter = document.getElementById('packages-filter-type').value;

            const filtered = packagesList.filter(p => {{
                const matchesSearch = p.name.toLowerCase().includes(query) || p.license.toLowerCase().includes(query);
                const matchesType = typeFilter === 'all' || p.type.startsWith(typeFilter);
                return matchesSearch && matchesType;
            }});

            renderPackagesTable(filtered);
        }}

        // Select dependency for details view
        function selectPackage(pkg) {{
            selectedPackageId = pkg.spdxId;
            
            // Re-render rows to update selection highlighting
            document.querySelectorAll('#packages-table-body tr').forEach((tr, idx) => {{
                const pkgs = packagesList; // Needs to align with active visible packages but simple check:
                tr.classList.remove('selected');
            }});
            event.currentTarget.classList.add('selected');

            document.getElementById('package-detail-empty').style.display = 'none';
            document.getElementById('package-detail-content').style.display = 'block';

            document.getElementById('p-detail-name').textContent = pkg.name;
            document.getElementById('p-detail-tag').textContent = pkg.type;
            document.getElementById('p-detail-version').textContent = pkg.version;
            document.getElementById('p-detail-license').textContent = pkg.license;
            document.getElementById('p-detail-purl').textContent = pkg.purl || 'N/A';
            document.getElementById('p-detail-manifest').textContent = pkg.manifest;
            document.getElementById('p-detail-spdxref').textContent = pkg.spdxId;
        }}

        // Render Files Table
        function renderFilesTable() {{
            const tbody = document.getElementById('files-table-body');
            const empty = document.getElementById('files-empty');
            tbody.innerHTML = '';
            
            if (filteredFiles.length === 0) {{
                empty.style.display = 'flex';
                document.getElementById('pagination-info').textContent = 'Showing 0-0 of 0 files';
                return;
            }}
            
            empty.style.display = 'none';
            
            const start = (currentFilesPage - 1) * itemsPerPage;
            const end = Math.min(start + itemsPerPage, filteredFiles.length);
            
            document.getElementById('pagination-info').textContent = `Showing ${{start + 1}}-${{end}} of ${{filteredFiles.length}} files`;
            
            // Enable/disable page buttons
            document.getElementById('prev-page-btn').disabled = currentFilesPage === 1;
            document.getElementById('next-page-btn').disabled = end >= filteredFiles.length;

            const pageItems = filteredFiles.slice(start, end);
            
            pageItems.forEach(file => {{
                const tr = document.createElement('tr');
                if (selectedFileId === file.spdxId) tr.className = 'selected';
                
                tr.onclick = () => selectFile(file);
                
                tr.innerHTML = `
                    <td title="${{file.path}}"><strong>${{file.name}}</strong><br><span style="font-size:11px;color:var(--text-muted);">${{file.path}}</span></td>
                    <td>${{file.size > 0 ? (file.size/1024).toFixed(1) + ' KB' : 'N/A'}}</td>
                    <td><span class="tag ${{file.license !== 'NOASSERTION' ? 'tag-success' : 'tag-danger'}}">${{file.license}}</span></td>
                `;
                tbody.appendChild(tr);
            }});
        }}

        // Filter files based on search / license selector
        function filterFiles(page = 1) {{
            const query = document.getElementById('files-search').value.toLowerCase();
            const licenseFilter = document.getElementById('files-filter-license').value;

            filteredFiles = filesList.filter(f => {{
                const matchesSearch = f.path.toLowerCase().includes(query) || f.license.toLowerCase().includes(query);
                const matchesLicense = licenseFilter === 'all' || f.license === licenseFilter;
                return matchesSearch && matchesLicense;
            }});

            currentFilesPage = page;
            renderFilesTable();
        }}

        // Pagination buttons handlers
        function prevPage() {{
            if (currentFilesPage > 1) {{
                currentFilesPage--;
                renderFilesTable();
            }}
        }}

        function nextPage() {{
            if (currentFilesPage * itemsPerPage < filteredFiles.length) {{
                currentFilesPage++;
                renderFilesTable();
            }}
        }}

        // Select file for details view
        function selectFile(file) {{
            selectedFileId = file.spdxId;
            
            // Re-render current page selection highlighting
            document.querySelectorAll('#files-table-body tr').forEach(tr => {{
                tr.classList.remove('selected');
            }});
            event.currentTarget.classList.add('selected');

            document.getElementById('file-detail-empty').style.display = 'none';
            document.getElementById('file-detail-content').style.display = 'block';

            document.getElementById('f-detail-name').textContent = file.name;
            document.getElementById('f-detail-path').textContent = file.path;
            document.getElementById('f-detail-size').textContent = file.size > 0 ? file.size.toLocaleString() + ' bytes' : 'N/A';
            document.getElementById('f-detail-license').textContent = file.license;
            document.getElementById('f-detail-sha256').textContent = file.sha256 || 'N/A';
            document.getElementById('f-detail-sha1').textContent = file.sha1 || 'N/A';
            document.getElementById('f-detail-spdxref').textContent = file.spdxId;
        }}
    </script>
</body>
</html>
"""
        return html_content
