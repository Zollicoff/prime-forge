#!/usr/bin/env python3
"""
GitHub Agent Radar - Discover interesting AI agent repos

Tracks repos related to AI agents, analyzes recent activity,
and surfaces interesting projects worth following.
"""

import json
import subprocess
import sys
from datetime import datetime, timedelta
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class RepoInfo:
    """Repository metadata"""
    full_name: str
    description: str
    stars: int
    language: str
    pushed_at: str
    url: str
    topics: List[str]
    
    @property
    def days_since_push(self) -> int:
        """Calculate days since last push"""
        pushed = datetime.fromisoformat(self.pushed_at.replace('Z', '+00:00'))
        return (datetime.now(pushed.tzinfo) - pushed).days


def search_repos(query: str, limit: int = 50) -> List[RepoInfo]:
    """Search GitHub for repos matching query"""
    fields = ["name", "owner", "description", "stargazersCount", 
              "language", "pushedAt", "url"]
    
    cmd = [
        "gh", "search", "repos", query,
        "--sort", "updated",
        "--limit", str(limit),
        "--json", ",".join(fields)
    ]
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Error searching repos: {result.stderr}", file=sys.stderr)
        return []
    
    data = json.loads(result.stdout)
    
    repos = []
    for item in data:
        owner = item["owner"]["login"]
        name = item["name"]
        lang = item.get("language", "Unknown") or "Unknown"
        
        # Topics not available in search, would need separate API call
        topics = []
        
        repos.append(RepoInfo(
            full_name=f"{owner}/{name}",
            description=item.get("description", "No description"),
            stars=item["stargazersCount"],
            language=lang,
            pushed_at=item["pushedAt"],
            url=item["url"],
            topics=topics
        ))
    
    return repos


def filter_interesting(repos: List[RepoInfo], 
                       min_stars: int = 100,
                       max_days_old: int = 7) -> List[RepoInfo]:
    """Filter for interesting, recently active repos"""
    return [
        r for r in repos 
        if r.stars >= min_stars and r.days_since_push <= max_days_old
    ]


def format_repo(repo: RepoInfo) -> str:
    """Format repo info for display"""
    topics_str = ", ".join(repo.topics[:5]) if repo.topics else "no topics"
    
    return f"""
🦞 {repo.full_name} ({repo.stars:,}⭐)
   {repo.description}
   📝 {repo.language} | 🏷️  {topics_str}
   ⏰ Updated {repo.days_since_push} days ago
   🔗 {repo.url}
"""


def main():
    """Main radar scan"""
    print("🔍 GitHub Agent Radar - Scanning...")
    print("=" * 60)
    
    # Search queries
    queries = [
        "ai agent in:name,description,topics",
        "autonomous agent language:Python",
        "openclaw in:name,description",
    ]
    
    all_repos = []
    seen = set()
    
    for query in queries:
        print(f"\n📡 Searching: {query}")
        repos = search_repos(query, limit=20)
        
        # Deduplicate
        for repo in repos:
            if repo.full_name not in seen:
                all_repos.append(repo)
                seen.add(repo.full_name)
    
    # Filter for interesting recent activity
    interesting = filter_interesting(all_repos, min_stars=500, max_days_old=7)
    
    print(f"\n\n✨ Found {len(interesting)} interesting repos (500+ stars, updated in last 7 days):")
    print("=" * 60)
    
    # Sort by stars
    interesting.sort(key=lambda r: r.stars, reverse=True)
    
    for repo in interesting:
        print(format_repo(repo))
    
    # Stats
    print("\n📊 Statistics:")
    print(f"   Total repos scanned: {len(all_repos)}")
    print(f"   Interesting repos: {len(interesting)}")
    
    languages = {}
    for repo in interesting:
        languages[repo.language] = languages.get(repo.language, 0) + 1
    
    print(f"\n   Top languages:")
    for lang, count in sorted(languages.items(), key=lambda x: x[1], reverse=True)[:5]:
        print(f"      {lang}: {count}")
    
    # Save results
    output_file = "tmp/gh-agent-radar/radar-results.json"
    with open(output_file, "w") as f:
        json.dump({
            "scan_time": datetime.now().isoformat(),
            "repos": [
                {
                    "full_name": r.full_name,
                    "description": r.description,
                    "stars": r.stars,
                    "language": r.language,
                    "days_since_push": r.days_since_push,
                    "url": r.url,
                    "topics": r.topics
                }
                for r in interesting
            ]
        }, f, indent=2)
    
    print(f"\n💾 Results saved to {output_file}")


if __name__ == "__main__":
    main()
