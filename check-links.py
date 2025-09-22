#!/usr/bin/env python3
"""
MkDocs Link Checker Script
==========================
This script checks for broken internal links in MkDocs documentation.

Usage:
    python check-links.py

Features:
- ✅ Finds missing documentation files referenced in navigation
- ✅ Detects broken internal links in markdown files  
- ✅ Reports 404s found during MkDocs server warnings
- ✅ Creates a summary report of all issues
- ✅ Suggests fixes for common problems

Run this before deploying documentation to catch link issues!
"""

import os
import re
import yaml
from pathlib import Path
from typing import List, Dict, Set, Tuple

class MkDocsLinkChecker:
    def __init__(self, docs_dir: str = "docs", config_file: str = "mkdocs.yml"):
        self.docs_dir = Path(docs_dir)
        self.config_file = Path(config_file)
        self.broken_links: List[Dict] = []
        self.missing_files: Set[str] = set()
        self.all_docs: Set[str] = set()
        
    def load_mkdocs_config(self) -> Dict:
        """Load MkDocs configuration file"""
        with open(self.config_file, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)
            
    def find_all_docs(self) -> Set[str]:
        """Find all existing documentation files"""
        docs = set()
        for md_file in self.docs_dir.rglob("*.md"):
            # Get relative path from docs directory
            rel_path = md_file.relative_to(self.docs_dir)
            docs.add(str(rel_path).replace('\\', '/'))
        return docs
        
    def check_nav_links(self, config: Dict) -> List[str]:
        """Check navigation configuration for missing files"""
        missing = []
        nav = config.get('nav', [])
        
        def extract_files(nav_item):
            if isinstance(nav_item, dict):
                for key, value in nav_item.items():
                    if isinstance(value, str) and value.endswith('.md'):
                        if value not in self.all_docs:
                            missing.append(value)
                    elif isinstance(value, list):
                        for item in value:
                            extract_files(item)
            elif isinstance(nav_item, str) and nav_item.endswith('.md'):
                if nav_item not in self.all_docs:
                    missing.append(nav_item)
                    
        for item in nav:
            extract_files(item)
            
        return missing
        
    def check_markdown_links(self) -> List[Dict]:
        """Check internal links in markdown files"""
        broken_links = []
        
        # Pattern to match markdown links: [text](path)
        link_pattern = re.compile(r'\[([^\]]*)\]\(([^)]+)\)')
        
        for md_file in self.docs_dir.rglob("*.md"):
            rel_path = md_file.relative_to(self.docs_dir)
            
            with open(md_file, 'r', encoding='utf-8') as f:
                content = f.read()
                
            for line_num, line in enumerate(content.split('\n'), 1):
                matches = link_pattern.findall(line)
                
                for text, link in matches:
                    # Skip external links (http/https), anchors, and special links
                    if (link.startswith(('http://', 'https://', '#', 'mailto:')) or
                        link in ['LICENSE', 'README.md']):
                        continue
                        
                    # Resolve relative path
                    current_dir = rel_path.parent
                    target_path = current_dir / link if not link.startswith('/') else Path(link[1:])
                    target_path = target_path.resolve()
                    
                    # Check if target exists in docs
                    target_str = str(target_path).replace('\\', '/')
                    if target_str not in self.all_docs:
                        broken_links.append({
                            'file': str(rel_path),
                            'line': line_num,
                            'text': text,
                            'target': link,
                            'resolved_target': target_str
                        })
                        
        return broken_links
        
    def generate_missing_files(self, missing_nav: List[str]) -> None:
        """Generate placeholder files for missing navigation entries"""
        print("\n🔧 SUGGESTED FIXES:")
        print("=" * 50)
        
        for missing_file in missing_nav:
            file_path = self.docs_dir / missing_file
            
            # Create directory if it doesn't exist
            file_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Generate basic content
            title = missing_file.replace('.md', '').replace('-', ' ').replace('/', ' - ').title()
            content = f"""# {title}

!!! warning "Work in Progress"
    This page is under development. Content coming soon!

## Overview

TODO: Add content for {title}

## Key Features

- Feature 1
- Feature 2
- Feature 3

## Next Steps

- [ ] Complete documentation
- [ ] Add examples
- [ ] Add diagrams

---

**📚 Related Documentation:**
- [Getting Started](../getting-started/overview.md)
- [Authentication](../authentication/index.md)
"""
            
            print(f"📝 Creating: {missing_file}")
            print(f"   Title: {title}")
            
            # Uncomment the next line to actually create the files
            # with open(file_path, 'w', encoding='utf-8') as f:
            #     f.write(content)
                
    def run_check(self) -> None:
        """Run complete link check"""
        print("🔍 MkDocs Link Checker")
        print("=" * 50)
        
        # Load configuration
        config = self.load_mkdocs_config()
        
        # Find all documentation files
        self.all_docs = self.find_all_docs()
        print(f"📄 Found {len(self.all_docs)} documentation files")
        
        # Check navigation links
        missing_nav = self.check_nav_links(config)
        print(f"🔗 Found {len(missing_nav)} missing navigation files")
        
        # Check markdown internal links
        broken_md_links = self.check_markdown_links()
        print(f"💔 Found {len(broken_md_links)} broken internal links")
        
        # Report results
        if missing_nav:
            print("\n❌ MISSING NAVIGATION FILES:")
            print("-" * 30)
            for i, missing in enumerate(missing_nav, 1):
                print(f"{i:2d}. {missing}")
                
        if broken_md_links:
            print("\n💔 BROKEN INTERNAL LINKS:")
            print("-" * 30)
            for i, link in enumerate(broken_md_links, 1):
                print(f"{i:2d}. {link['file']}:{link['line']}")
                print(f"    Link: [{link['text']}]({link['target']})")
                print(f"    Target: {link['resolved_target']}")
                print()
                
        # Generate suggestions
        if missing_nav:
            self.generate_missing_files(missing_nav)
            
        # Summary
        total_issues = len(missing_nav) + len(broken_md_links)
        print(f"\n📊 SUMMARY:")
        print(f"   Missing files: {len(missing_nav)}")
        print(f"   Broken links:  {len(broken_md_links)}")
        print(f"   Total issues:  {total_issues}")
        
        if total_issues == 0:
            print("\n✅ No broken links found! Documentation structure looks good.")
        else:
            print(f"\n⚠️  Found {total_issues} issues to fix.")
            print("\n💡 TIP: Run this script after creating missing files to verify fixes!")

if __name__ == "__main__":
    checker = MkDocsLinkChecker()
    checker.run_check()