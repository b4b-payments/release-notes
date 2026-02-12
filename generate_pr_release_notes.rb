#!/usr/bin/env ruby
# frozen_string_literal: true

# Generates release notes for a single pull request.
# Designed to run in GitHub Actions CI (no external gem dependencies).
#
# Usage:
#   ruby generate_pr_release_notes.rb --pr 123 --base origin/main --head pr_head [--verbose]
#
# Required environment variables:
#   RN_ANTHROPIC_API_KEY  - Anthropic API key for Claude
#
# Optional environment variables:
#   RN_GH_ACCESS_TOKEN    - GitHub token for fetching PR details
#   RN_JIRA_BASE_URL      - Jira instance URL
#   RN_JIRA_CLOUD_ID      - Atlassian Cloud ID
#   RN_JIRA_EMAIL         - Atlassian account email
#   RN_ATLASSIAN_API_TOKEN - Atlassian API token
#   RN_ANTHROPIC_MODEL    - Claude model (default: claude-haiku-4-5)

require 'json'
require 'net/http'
require 'uri'
require 'base64'
require 'optparse'
require 'time'
require 'open3'

class PRReleaseNotesGenerator
  JIRA_PATTERN = /\b([A-Z]+-\d+)\b/
  GIT_REF_PATTERN = %r{\A[\w\-./]+\z}

  def initialize(options = {})
    @pr_number = options[:pr_number]
    @base_ref = options[:base_ref]
    @head_ref = options[:head_ref]
    @verbose = options[:verbose] || false

    @anthropic_api_key = ENV["RN_ANTHROPIC_API_KEY"]
    @anthropic_model = ENV["RN_ANTHROPIC_MODEL"] || "claude-haiku-4-5"

    @github_token = ENV["RN_GH_ACCESS_TOKEN"]
    @github_repo = extract_github_repo

    @jira_base_url = ENV["RN_JIRA_BASE_URL"]
    @jira_cloud_id = ENV["RN_JIRA_CLOUD_ID"]
    @jira_email = ENV["RN_JIRA_EMAIL"]
    @atlassian_api_token = ENV["RN_ATLASSIAN_API_TOKEN"]

    validate!
  end

  def generate
    log("Generating release notes for PR ##{@pr_number}...")
    log("Comparing: #{@base_ref}..#{@head_ref}")

    pr_details = fetch_pr_details

    commits = extract_commits
    log("Found #{commits.length} commits")

    if commits.empty?
      output_no_changes
      return
    end

    file_changes = extract_file_changes
    log("#{file_changes[:total_files]} files changed")

    jira_ticket_ids = extract_all_jira_tickets(commits, pr_details)
    log("Found #{jira_ticket_ids.length} Jira tickets")

    jira_details = fetch_jira_details_if_available(jira_ticket_ids)

    context = build_context(pr_details, commits, file_changes, jira_ticket_ids, jira_details)
    release_notes = generate_release_notes(context)

    output_release_notes(release_notes, pr_details, commits, jira_ticket_ids)
  end

  private

  def validate!
    errors = []
    errors << "PR number is required (--pr)" unless @pr_number
    errors << "PR number must be a positive integer" if @pr_number && @pr_number <= 0
    errors << "Base ref is required (--base)" unless @base_ref
    errors << "Head ref is required (--head)" unless @head_ref
    errors << "ANTHROPIC_API_KEY environment variable is required" unless @anthropic_api_key

    if @base_ref && !@base_ref.match?(GIT_REF_PATTERN)
      errors << "Base ref contains invalid characters: #{@base_ref}"
    end

    if @head_ref && !@head_ref.match?(GIT_REF_PATTERN)
      errors << "Head ref contains invalid characters: #{@head_ref}"
    end

    if errors.any?
      errors.each { |e| warn("[ERROR] #{e}") }
      exit(1)
    end
  end

  def extract_github_repo
    remote_url = git("config", "--get", "remote.origin.url")
    match = remote_url.match(%r{(?:git@github\.com:|https://github\.com/)([^/]+)/(.+?)(?:\.git)?$})

    if match
      { owner: match[1], repo: match[2].sub(/\.git$/, "") }
    end
  end

  def fetch_pr_details
    return unless @github_token && @github_repo

    log("Fetching PR ##{@pr_number} details from GitHub...")

    uri = URI("https://api.github.com/repos/#{@github_repo[:owner]}/#{@github_repo[:repo]}/pulls/#{@pr_number}")
    request = Net::HTTP::Get.new(uri)
    request["Authorization"] = "Bearer #{@github_token}"
    request["Accept"] = "application/vnd.github+json"
    request["X-GitHub-Api-Version"] = "2022-11-28"

    response = make_https_request(uri, request)

    if response.code == "200"
      data = JSON.parse(response.body)
      {
        number: data["number"],
        title: data["title"],
        description: data["body"],
        author: data["user"]["login"],
        branch: data["head"]["ref"],
        base_branch: data["base"]["ref"],
        url: data["html_url"],
        labels: data["labels"]&.map { |l| l["name"] } || [],
      }
    else
      log("Warning: Could not fetch PR details: #{response.code}")
      nil
    end
  rescue => e
    log("Warning: Error fetching PR details: #{e.message}")
    nil
  end

  def extract_commits
    merge_base = git("merge-base", @base_ref, @head_ref, allow_failure: true)

    if merge_base.empty?
      warn("[ERROR] Could not find merge base between #{@base_ref} and #{@head_ref}")
      exit(1)
    end

    output = git("log", "#{merge_base}..#{@head_ref}",
      "--pretty=format:%H|%an|%ae|%ad|%s|||%b|||", "--date=iso")

    commits = []
    output.split("|||\n").each do |block|
      next if block.strip.empty?

      lines = block.split("\n")
      first_line = lines.first
      body_lines = lines[1..] || []

      hash, author, email, date, subject = first_line.split("|", 5)
      body = body_lines.join("\n").gsub("|||", "").strip

      commits << {
        hash: hash,
        short_hash: hash&.[](0..7),
        author: author,
        email: email,
        date: date,
        subject: subject,
        body: body,
      }
    end

    commits
  end

  def extract_file_changes
    merge_base = git("merge-base", @base_ref, @head_ref)
    stats = git("diff", "--stat", "#{merge_base}..#{@head_ref}")
    changed_files = git("diff", "--name-only", "#{merge_base}..#{@head_ref}").split("\n").reject(&:empty?)

    categorized = {}
    changed_files.each do |file|
      category = case file
      when %r{^db/migrate/} then :migrations
      when %r{^app/models/} then :models
      when %r{^app/controllers/} then :controllers
      when %r{^app/services/} then :services
      when %r{^config/} then :config
      when %r{^(test|spec)/} then :tests
      when %r{^app/views/} then :views
      when %r{^lib/} then :libs
      else :other
      end
      (categorized[category] ||= []) << file
    end

    {
      stats: stats,
      total_files: changed_files.length,
      changed_files: changed_files,
      categorized: categorized,
    }
  end

  def extract_all_jira_tickets(commits, pr_details)
    tickets = Set.new

    commits.each do |commit|
      text = "#{commit[:subject]} #{commit[:body]}"
      tickets.merge(text.scan(JIRA_PATTERN).flatten)
    end

    if pr_details
      [:title, :description, :branch].each do |field|
        next unless (text = pr_details[field])
        tickets.merge(text.upcase.scan(JIRA_PATTERN).flatten)
      end
    end

    tickets.to_a.sort
  end

  def jira_configured?
    @jira_base_url && @jira_cloud_id && @jira_email && @atlassian_api_token
  end

  def fetch_jira_details_if_available(ticket_ids)
    return [] unless jira_configured? && ticket_ids.any?

    log("Fetching #{ticket_ids.length} Jira ticket details...")
    auth = Base64.strict_encode64("#{@jira_email}:#{@atlassian_api_token}")

    ticket_ids.map.with_index do |ticket_id, index|
      uri = URI("https://api.atlassian.com/ex/jira/#{@jira_cloud_id}/rest/api/3/issue/#{ticket_id}")
      request = Net::HTTP::Get.new(uri)
      request["Authorization"] = "Basic #{auth}"
      request["Accept"] = "application/json"

      response = make_https_request(uri, request)

      if response.code == "200"
        data = JSON.parse(response.body)
        {
          key: ticket_id,
          summary: data.dig("fields", "summary"),
          type: data.dig("fields", "issuetype", "name"),
          status: data.dig("fields", "status", "name"),
          priority: data.dig("fields", "priority", "name"),
        }
      else
        { key: ticket_id, error: "HTTP #{response.code}" }
      end
    rescue StandardError => e
      { key: ticket_id, error: e.message }
    ensure
      sleep(0.3) if index && index < ticket_ids.length - 1
    end
  end

  def build_context(pr_details, commits, file_changes, jira_ticket_ids, jira_details)
    <<~CONTEXT
      # Pull Request Context

      ## PR Details
      - PR Number: ##{@pr_number}
      - Title: #{pr_details&.[](:title) || "N/A"}
      - Author: #{pr_details&.[](:author) || "N/A"}
      - Branch: #{pr_details&.[](:branch) || @head_ref}
      - Base: #{pr_details&.[](:base_branch) || @base_ref}
      - Labels: #{pr_details&.[](:labels)&.join(", ").then { |l| l&.empty? ? "None" : l } || "None"}

      ## PR Description
      #{pr_details&.[](:description) || "No description provided."}

      ## Commits (#{commits.length})
      #{commits.map { |c| "- `#{c[:short_hash]}` #{c[:subject]} (#{c[:author]})" }.join("\n")}

      ## File Changes (#{file_changes[:total_files]} files)
      #{file_changes[:stats]}

      ## Files by Category
      #{format_file_categories(file_changes[:categorized])}

      ## Jira Tickets
      #{format_jira_context(jira_ticket_ids, jira_details)}
    CONTEXT
  end

  def format_file_categories(categorized)
    return "No files changed." if categorized.empty?

    categorized.map do |category, files|
      "**#{category}** (#{files.length}):\n#{files.map { |f| "  - #{f}" }.join("\n")}"
    end.join("\n\n")
  end

  def format_jira_context(ticket_ids, jira_details)
    return "No Jira tickets referenced." if ticket_ids.empty?

    if jira_details.any?
      jira_details.map do |t|
        if t[:error]
          "- **#{t[:key]}**: Could not fetch details (#{t[:error]})"
        else
          "- **#{t[:key]}**: #{t[:summary]} (#{t[:type]}, #{t[:status]}, #{t[:priority]})"
        end
      end.join("\n")
    else
      ticket_ids.map { |id| "- #{id}" }.join("\n")
    end
  end

  def generate_release_notes(context)
    prompt = <<~PROMPT
      #{context}

      ---

      Based on the pull request context above, generate concise release notes for this PR.
      The release notes will be posted as a comment on the pull request for review and approval before merging.

      Format your response as markdown with these sections:

      ### Summary
      A 1-3 sentence overview of what this PR does and why.

      ### Changes
      A bulleted list of the key changes, grouped logically. Focus on what changed from a user/system perspective, not individual file changes. Be specific but concise.

      ### Risk Assessment
      Rate as **LOW** / **MEDIUM** / **HIGH** with a brief explanation. Consider:
      - Database migrations
      - API changes
      - Configuration changes
      - External service integrations
      - Scope of code changes

      ### Jira Tickets
      List any referenced Jira tickets with their summary (if available).

      Guidelines:
      - Write for a technical audience (developers, QA, release managers)
      - Be factual and specific; avoid vague statements
      - Highlight any breaking changes, new dependencies, or required configuration
      - If there are database migrations, mention them explicitly
      - Keep the total response under 500 words
      - Output ONLY the release notes content in markdown, no preamble or wrapping
    PROMPT

    call_llm(prompt, 2000)
  end

  def call_llm(prompt, max_tokens = 1000)
    log("Calling Anthropic API (#{@anthropic_model})...")

    uri = URI("https://api.anthropic.com/v1/messages")
    request = Net::HTTP::Post.new(uri)
    request["Content-Type"] = "application/json"
    request["x-api-key"] = @anthropic_api_key
    request["anthropic-version"] = "2023-06-01"

    request.body = {
      model: @anthropic_model,
      max_tokens: max_tokens,
      messages: [{ role: "user", content: prompt }],
    }.to_json

    response = make_https_request(uri, request, read_timeout: 120)

    if response.code == "200"
      result = JSON.parse(response.body)
      result["content"][0]["text"]
    else
      warn("[ERROR] Anthropic API error: #{response.code}")
      begin
        error_data = JSON.parse(response.body)
        warn("[ERROR] #{error_data.dig("error", "type")}: #{error_data.dig("error", "message")}")
      rescue JSON::ParserError
        warn("[ERROR] Could not parse error response")
      end
      exit(1)
    end
  rescue StandardError => e
    warn("[ERROR] Failed to call Anthropic API: #{e.message}")
    exit(1)
  end

  def output_no_changes
    puts <<~MD
      ## Release Notes

      > PR ##{@pr_number} | No changes detected

      No commits found between the base and head references.

      ---
      <sub>Generated by release-notes-bot. Approve with <code>/release-notes-approve</code> | Revoke with <code>/release-notes-revoke</code></sub>
    MD
  end

  def output_release_notes(notes, pr_details, commits, jira_ticket_ids)
    head_sha = git("rev-parse", @head_ref)[0..7]

    puts <<~MD
      ## Release Notes

      > PR ##{@pr_number} | `#{head_sha}` | #{commits.length} commit(s) | #{pr_details&.[](:author) || "unknown"}

      #{notes}

      ---
      <sub>Generated by release-notes-bot at commit <code>#{head_sha}</code>. Approve with <code>/release-notes-approve</code> | Revoke with <code>/release-notes-revoke</code></sub>
    MD
  end

  # Executes a git command safely using Open3 (no shell interpolation).
  def git(*args, allow_failure: false)
    stdout, stderr, status = Open3.capture3("git", *args)

    unless status.success? || allow_failure
      warn("[ERROR] git #{args.join(" ")} failed (exit #{status.exitstatus})")
      warn("[ERROR] #{stderr.strip}") unless stderr.strip.empty?
      exit(1)
    end

    stdout.strip
  end

  def make_https_request(uri, request, read_timeout: 30)
    http = Net::HTTP.new(uri.hostname, uri.port)
    http.use_ssl = true
    http.read_timeout = read_timeout
    http.request(request)
  end

  def log(message)
    warn(message) if @verbose
  end
end

# --- Main ---

options = {}

parser = OptionParser.new do |opts|
  opts.banner = "Usage: #{File.basename($0)} [options]"
  opts.separator ""
  opts.separator "Generate release notes for a pull request."
  opts.separator ""
  opts.separator "Required:"
  opts.on("--pr NUMBER", Integer, "Pull request number") { |n| options[:pr_number] = n }
  opts.on("--base REF", "Base git reference (e.g., origin/main)") { |r| options[:base_ref] = r }
  opts.on("--head REF", "Head git reference (e.g., pr_head)") { |r| options[:head_ref] = r }
  opts.separator ""
  opts.separator "Optional:"
  opts.on("-v", "--verbose", "Verbose output to stderr") { options[:verbose] = true }
  opts.on("-h", "--help", "Show help") { puts opts; exit }
end

begin
  parser.parse!
rescue OptionParser::InvalidOption => e
  warn(e)
  warn(parser)
  exit(1)
end

generator = PRReleaseNotesGenerator.new(options)
generator.generate
