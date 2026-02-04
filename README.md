*This is a submission for the [GitHub Copilot CLI Challenge](https://dev.to/challenges/github-2026-01-21)*

![Cover image: network diagnostics terminal](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/953ogodmrkdrdsirbxxj.png)

## What I Built
I built a Test-NetConnection interactive assistant that runs continuous network checks to a target host, logs results, and provides both statistical summaries and AI-powered observations. The assistant supports background monitoring tasks, listing active jobs, and on-demand log analysis. It’s designed for quick, repeatable troubleshooting of latency spikes and packet loss without leaving the terminal.

Key features:
- `/run <host> <minutes> <threshold_ms>` starts a background monitoring task.
- `/list` shows active or completed background tasks.
- `/analysis` summarizes logs and uses GitHub Copilot to produce AI observations.
- JSONL logging for both raw events and alerts.

## Demo
Run the assistant:

- `python .\tnc_interactiveAssistant.py`

Example session:
- Start a monitor: `/run 8.8.8.8 1 120`
- List tasks: `/list`
- Analyze logs with AI observations: `/analysis`

Demo video/screenshot: [Add link here]

## My Experience with GitHub Copilot CLI
I used GitHub Copilot CLI to quickly iterate on command handling, background task orchestration, and the AI analysis flow. It helped me:
- Draft the command parsing and task management scaffolding.
- Refactor analysis logic into reusable prompt context builders.
- Improve robustness with error handling and clean output formatting.

It accelerated development while keeping the solution focused on a clean CLI experience.

## Technologies
- Python 3.10+
- GitHub Copilot SDK
- Asyncio for Concurrency

## Repository 

## Author
GitHub: @turbotmy