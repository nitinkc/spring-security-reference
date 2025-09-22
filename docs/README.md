# MkDocs Documentation Setup

This directory contains the MkDocs configuration and documentation source files for the Spring Security Reference Project.

## 🚀 Quick Start

### 1. Install MkDocs

```bash
# Install Python dependencies
pip install -r requirements.txt

# Or install individually
pip install mkdocs-material
```

### 2. Serve Documentation Locally

```bash
# Start development server
python -m mkdocs serve

# Open browser to http://localhost:8000
```

### 3. Build Static Site

```bash
# Build static site
python -m mkdocs build

# Output will be in site/ directory
```

## 🎨 Customization

### Theme Configuration

The documentation uses Material for MkDocs with custom colors and features:

- **Primary Color**: Green (Spring theme)
- **Accent Color**: Teal
- **Dark/Light Mode**: Auto-switching based on system preference
- **Features**: Navigation tabs, search, code copying, syntax highlighting

### Adding Content

1. **Create new markdown files** in appropriate directories
2. **Update navigation** in `mkdocs.yml`
3. **Use Material extensions** for enhanced formatting
4. **Include diagrams** with Mermaid syntax

### Markdown Extensions

Available extensions include:

- **Code highlighting** with syntax highlighting
- **Admonitions** for notes, warnings, tips
- **Mermaid diagrams** for flowcharts and sequences
- **Tabbed content** for organized information
- **Task lists** with checkboxes
- **Mathematical expressions** with MathJax

## 🚀 Deployment Options

### GitHub Pages

1. **Create `.github/workflows/docs.yml`**:

```yaml
name: Deploy Documentation
on:
  push:
    branches: [ main ]
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    - uses: actions/setup-python@v4
      with:
        python-version: 3.x
    - run: pip install -r requirements.txt
    - run: python -m mkdocs gh-deploy --force
```

2. **Enable GitHub Pages** in repository settings
3. **Set source** to `gh-pages` branch


## 🔧 Development

### Live Reloading

The development server automatically reloads when files change:

```bash
python -m mkdocs serve --dev-addr=0.0.0.0:8000
```

### Validation

Check for broken links and validate structure:

```bash
python -m mkdocs build --strict
```

## 💡 Tips

- **Use emoji sparingly** but consistently for visual cues
- **Include diagrams** for complex authentication flows
- **Provide complete examples** with expected outputs
- **Cross-link sections** to improve navigation
- **Keep content up-to-date** with code changes

### The Magic of mkdocs gh-deploy: 

First, `mkdocs` builds your static website from your Markdown files in the docs directory, creating all the necessary HTML, CSS, and JavaScript files.

Second, it automatically commits and pushes this newly built static site to a branch named `gh-pages` in your repository. The `--force` flag ensures it overwrites the previous content.
In summary:

The `gh-pages` branch is a special branch that only contains the compiled, ready-to-view website. Your source code (the Markdown files) lives in the main branch. The GitHub Action acts as a bridge, automatically building the site from main and publishing the result to gh-pages whenever you update main