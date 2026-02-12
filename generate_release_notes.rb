#!/usr/bin/env ruby
# frozen_string_literal: true

require "json"
require "net/http"
require "uri"
require "base64"
require "optparse"
require "set"
require "time"
require "openssl"
require "dotenv"
require "fileutils"
require_relative "confluence_client"

Dotenv.load(".env.local")

class DeploymentSummaryGenerator
  JIRA_PATTERN = /\b([A-Z]+-\d+)\b/
  JIRA_URL_PATTERN = %r{https://[^/]+\.atlassian\.net/browse/([A-Z]+-\d+)}
  GITHUB_PR_URL_PATTERN = %r{https://github\.com/[^/]+/[^/]+/pull/(\d+)}
  GITHUB_PR_MERGE_PATTERN = /Merge pull request #(\d+)/

  # Confluence page/space IDs
  PROMPT_CONFIG_PAGE_ID = "3230269452"
  OUTPUT_PARENT_PAGE_ID = "3230859265" # the 2026 "directory"
  OUTPUT_SPACE_ID = "2106294276"

  def initialize(options = {})
    @base_ref = options[:base_ref] || "production"
    @compare_ref = options[:compare_ref] || "main"
    @output_dir = options[:output_dir] || "."
    @verbose = options[:verbose] || false
    @jira_base_url = ENV["RN_JIRA_BASE_URL"]
    @jira_cloud_id = ENV["RN_JIRA_CLOUD_ID"]
    @jira_email = ENV["RN_JIRA_EMAIL"]
    @atlassian_api_token = ENV["RN_ATLASSIAN_API_TOKEN"]
    @anthropic_api_key = ENV["RN_ANTHROPIC_API_KEY"]
    @anthropic_model = ENV["RN_ANTHROPIC_MODEL"] || "claude-haiku-4-5"
    @confluence_base_url = ENV["RN_CONFLUENCE_BASE_URL"]
    @github_access_token = ENV["RN_GH_ACCESS_TOKEN"]
    @file_changes_cache = nil
    @github_repo = nil

    validate_environment!
    validate_git_repository!
    extract_github_repo_from_git
    load_confluence_config!
  end

  def generate
    log("Starting deployment summary generation...")
    log("Comparing: #{@compare_ref} -> #{@base_ref}")
    log("")

    log("Step 1/6: Extracting commits...")
    commits = extract_commits

    if commits.empty?
      error("No commits found between #{@base_ref} and #{@compare_ref}")
      exit(1)
    end

    log("  Found #{commits.length} commits")

    log("Step 2/6: Analysing file changes...")
    file_changes = extract_file_changes
    @file_changes_cache = file_changes

    log("Step 3/6: Fetching pull request information from GitHub API...")
    commit_to_pr_map = fetch_prs_for_commits(commits)

    pull_requests_by_number = {}
    commit_to_pr_map.each_value do |pr_data|
      pull_requests_by_number[pr_data[:number]] = pr_data unless pull_requests_by_number[pr_data[:number]]
    end
    pull_requests = pull_requests_by_number.values
    log("  Found #{pull_requests.length} pull requests")

    log("Step 4/6: Extracting Jira tickets from commits and PR data...")
    jira_tickets_from_commits = extract_jira_tickets(commits)
    jira_tickets_from_prs = extract_jira_tickets_from_prs(commit_to_pr_map)
    all_jira_tickets = (jira_tickets_from_commits + jira_tickets_from_prs).uniq.sort
    log("  Found #{all_jira_tickets.length} Jira tickets (#{jira_tickets_from_commits.length} from commits, #{jira_tickets_from_prs.length} from PR data)")

    log("Step 5/6: Fetching Jira ticket details...")
    jira_details = fetch_jira_details(all_jira_tickets)
    log("  Successfully fetched #{jira_details.count { |t| !t[:error] }} tickets")

    log("Step 6/6: Grouping changes by pull request...")
    grouped_changes = group_commits_by_pr(commits, commit_to_pr_map)
    log("  Grouped #{grouped_changes[:pr_groups].length} PRs")
    log("  Found #{grouped_changes[:direct_commits][:commits].length} direct commits")

    timestamp = Time.now.strftime("%Y%m%d_%H%M%S")
    output_path = File.join(@output_dir, "tmp", "release_notes", timestamp)
    FileUtils.mkdir_p(output_path)
    log("  Output directory: #{output_path}")

    context = build_context(commits, file_changes, jira_details, pull_requests, grouped_changes)

    log("")
    log("Step 7/7: Publishing to Confluence...")
    publish_grouped_changes_to_confluence(grouped_changes, context, output_path, jira_details)
    log("")
  end

  private

  def validate_environment!
    missing = []
    missing << "RN_JIRA_BASE_URL" unless @jira_base_url
    missing << "RN_JIRA_CLOUD_ID" unless @jira_cloud_id
    missing << "RN_JIRA_EMAIL" unless @jira_email
    missing << "RN_ATLASSIAN_API_TOKEN" unless @atlassian_api_token
    missing << "RN_ANTHROPIC_API_KEY" unless @anthropic_api_key
    missing << "RN_CONFLUENCE_BASE_URL" unless @confluence_base_url

    if missing.any?
      error("Missing required environment variables: #{missing.join(", ")}")
      exit(1)
    end
  end

  def validate_git_repository!
    unless system("git rev-parse --git-dir > /dev/null 2>&1")
      error("Not in a git repository!")
      exit(1)
    end

    unless ref_exists?(@base_ref)
      error("Base reference '#{@base_ref}' does not exist!")
      exit(1)
    end

    unless ref_exists?(@compare_ref)
      error("Compare reference '#{@compare_ref}' does not exist!")
      exit(1)
    end
  end

  def ref_exists?(ref)
    system("git rev-parse --verify #{ref} > /dev/null 2>&1")
  end

  def extract_github_repo_from_git
    remote_url = %x(git config --get remote.origin.url).strip

    if remote_url.empty?
      error("Could not determine git remote URL")
      exit(1)
    end

    match = remote_url.match(%r{(?:git@github\.com:|https://github\.com/)([^/]+)/(.+?)(?:\.git)?$})

    if match
      owner = match[1]
      repo = match[2].sub(/\.git$/, "")
      @github_repo = { owner: owner, repo: repo }
      log("  GitHub repo detected: #{owner}/#{repo}")
    else
      error("Could not parse GitHub repository from remote URL: #{remote_url}")
      exit(1)
    end
  end

  def load_confluence_config!
    log("Loading section configuration from Confluence...")

    @confluence_client = ConfluenceClient.new(
      base_url: @confluence_base_url,
      api_token: @atlassian_api_token,
      email: @jira_email,
    )

    @confluence_config = @confluence_client.fetch_config_from_page(PROMPT_CONFIG_PAGE_ID, format: :yaml)
    log("  Successfully loaded Confluence config with #{@confluence_config["sections"]&.length || 0} sections")
  rescue => e
    error("Failed to load Confluence configuration: #{e.message}")
    exit(1)
  end

  def extract_commits
    merge_base = %x(git merge-base #{@base_ref} #{@compare_ref}).strip

    if merge_base.empty?
      error("Could not find merge base between references")
      exit(1)
    end

    commits_output = %x(git log #{merge_base}..#{@compare_ref} --pretty=format:'%H|%an|%ae|%ad|%s|||%b|||' --date=iso)

    commits = []
    commits_output.split("|||\n").each do |commit_block|
      next if commit_block.strip.empty?

      lines = commit_block.split("\n")
      first_line = lines.first
      body_lines = lines[1..-1] || []

      hash, author, email, date, subject = first_line.split("|", 5)
      body = body_lines.join("\n").gsub("|||", "").strip

      commits << {
        hash: hash,
        short_hash: hash[0..7],
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
    merge_base = %x(git merge-base #{@base_ref} #{@compare_ref}).strip
    stats = %x(git diff --stat #{merge_base}..#{@compare_ref}).strip
    changed_files = %x(git diff --name-only #{merge_base}..#{@compare_ref}).split("\n")
    categorized = categorize_files(changed_files)
    critical_patterns = [
      "app/models/",
      "app/controllers/api/",
      "app/services/",
      "lib/payment_processor/",
      "db/migrate/",
      "config/",
    ]

    critical_changes = {}
    critical_patterns.each do |pattern|
      files = changed_files.select { |f| f.start_with?(pattern) }
      next if files.empty?

      diff = %x(git diff #{merge_base}..#{@compare_ref} -- #{files.join(" ")})
      critical_changes[pattern] = {
        files: files,
        diff_size: diff.length,
      }
    end

    {
      stats: stats,
      total_files: changed_files.length,
      changed_files: changed_files,
      categorized: categorized,
      critical_changes: critical_changes,
    }
  end

  def categorize_files(files)
    categories = {
      migrations: [],
      models: [],
      controllers: [],
      services: [],
      config: [],
      tests: [],
      views: [],
      libs: [],
      other: [],
    }

    files.each do |file|
      case file
      when %r{^db/migrate/}
        categories[:migrations] << file
      when %r{^app/models/}
        categories[:models] << file
      when %r{^app/controllers/}
        categories[:controllers] << file
      when %r{^app/services/}
        categories[:services] << file
      when %r{^config/}
        categories[:config] << file
      when %r{^(test|spec)/}
        categories[:tests] << file
      when %r{^app/views/}
        categories[:views] << file
      when %r{^lib/}
        categories[:libs] << file
      else
        categories[:other] << file
      end
    end

    categories.reject { |_, v| v.empty? }
  end

  def extract_jira_tickets(commits)
    tickets = Set.new

    commits.each do |commit|
      full_message = "#{commit[:subject]} #{commit[:body]}"

      tickets.merge(full_message.scan(JIRA_PATTERN).flatten)
      tickets.merge(full_message.scan(JIRA_URL_PATTERN).flatten)
    end

    tickets.to_a.sort
  end

  def extract_jira_ticket_ids_from_commit(commit)
    full_message = "#{commit[:subject]} #{commit[:body]}"
    full_message.scan(JIRA_PATTERN).flatten.uniq
  end

  def extract_jira_ticket_ids_from_branch(branch_name)
    return [] unless branch_name

    branch_name.upcase.scan(JIRA_PATTERN)&.flatten&.uniq
  end

  def extract_jira_tickets_from_prs(commit_to_pr_map)
    commit_to_pr_map.each_value.with_object(Set.new) do |pr_data, tickets|
      next unless pr_data

      [:branch, :title, :description].each do |key|
        next unless (text = pr_data[key])

        tickets.merge(text.upcase.scan(JIRA_PATTERN).flatten)
      end
    end.to_a.sort
  end

  def fetch_prs_for_commits(commits)
    return {} if commits.empty?
    return {} unless @github_repo && @github_access_token

    commit_to_pr = {}

    commits.each_with_index do |commit, index|
      pr_data = fetch_pr_for_commit(commit[:hash], index, commits.length)
      commit_to_pr[commit[:hash]] = pr_data if pr_data
    end

    commit_to_pr
  end

  def fetch_pr_for_commit(commit_hash, index, total)
    log("  Fetching PR for commit #{commit_hash[0..7]} (#{index + 1}/#{total})...") if @verbose
    rate_limit_delay = 0.5

    uri = URI("https://api.github.com/repos/#{@github_repo[:owner]}/#{@github_repo[:repo]}/commits/#{commit_hash}/pulls")

    request = Net::HTTP::Get.new(uri)
    request["Authorization"] = "Bearer #{@github_access_token}"
    request["Accept"] = "application/vnd.github+json"
    request["X-GitHub-Api-Version"] = "2022-11-28"

    http = Net::HTTP.new(uri.hostname, uri.port)
    http.use_ssl = true
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE
    response = http.request(request)

    if response.code == "200"
      prs = JSON.parse(response.body)

      merged_pr = prs.find { |pr| pr["merged_at"] && pr["state"] == "closed" }

      if merged_pr
        return build_pr_from_github_data(merged_pr)
      end
    elsif response.code == "404"
      log("  [!] Commit #{commit_hash[0..7]} not found on GitHub") if @verbose
    elsif response.code == "403"
      error("  [!] GitHub API rate limited or auth failed: #{response.code}")
      error("  Response: #{response.body[0..200]}")
    elsif response.code != "200"
      log("  [!] Error fetching PR for #{commit_hash[0..7]}: #{response.code}") if @verbose
    end

    nil
  rescue => e
    log("  [!] Exception fetching PR for #{commit_hash[0..7]}: #{e.message}") if @verbose
    nil
  ensure
    sleep(rate_limit_delay) if index < total - 1
  end

  def build_pr_from_github_data(pr_data)
    {
      number: pr_data["number"],
      title: pr_data["title"],
      author: pr_data["user"]["login"],
      description: pr_data["body"],
      merged_at: pr_data["merged_at"],
      url: pr_data["html_url"],
      branch: pr_data["head"]["ref"],
    }
  end

  def fetch_jira_details(ticket_ids)
    return [] if ticket_ids.empty?

    auth = Base64.strict_encode64("#{@jira_email}:#{@atlassian_api_token}")
    rate_limit_delay = 0.5

    ticket_ids.map.with_index do |ticket_id, index|
      log("  Fetching #{ticket_id} (#{index + 1}/#{ticket_ids.length})...") if @verbose

      uri = URI("https://api.atlassian.com/ex/jira/#{@jira_cloud_id}/rest/api/3/issue/#{ticket_id}")
      log("  URL: #{uri}") if @verbose
      request = Net::HTTP::Get.new(uri)
      request["Authorization"] = "Basic #{auth}"
      request["Accept"] = "application/json"
      log("  Auth header set: #{request["Authorization"][0..20]}...") if @verbose

      http = Net::HTTP.new(uri.hostname, uri.port)
      http.use_ssl = true
      http.verify_mode = OpenSSL::SSL::VERIFY_NONE
      response = http.request(request)

      if response.code != "200"
        log("  Response code: #{response.code}") if @verbose
        log("  Response body: #{response.body[0..500]}") if @verbose
      end

      if response.code == "200"
        data = JSON.parse(response.body)
        {
          key: ticket_id,
          summary: data["fields"]["summary"],
          description: extract_description(data["fields"]["description"]),
          type: data["fields"]["issuetype"]["name"],
          status: data["fields"]["status"]["name"],
          priority: data["fields"]["priority"]&.fetch("name", "None"),
          components: data["fields"]["components"]&.map { |c| c["name"] },
          labels: data["fields"]["labels"],
          assignee: data["fields"]["assignee"]&.fetch("displayName", "Unassigned"),
        }
      else
        log("  [!] Warning: Could not fetch #{ticket_id}: #{response.code}") if @verbose
        { key: ticket_id, error: "HTTP #{response.code}" }
      end
    rescue => e
      log("  [!] Error fetching #{ticket_id}: #{e.message}") if @verbose
      { key: ticket_id, error: e.message }
    ensure
      sleep(rate_limit_delay) if index < ticket_ids.length - 1
    end
  end

  def extract_description(description_field)
    return unless description_field

    if description_field.is_a?(Hash)
      extract_text_from_adf(description_field)
    else
      description_field.to_s
    end
  end

  def extract_text_from_adf(node)
    return "" unless node.is_a?(Hash)

    text = []

    if node["text"]
      text << node["text"]
    end

    if node["content"].is_a?(Array)
      node["content"].each do |child|
        text << extract_text_from_adf(child)
      end
    end

    text.join(" ").strip
  end

  def build_context(commits, file_changes, jira_details, pull_requests = [], grouped_changes = {})
    {
      metadata: {
        base_ref: @base_ref,
        compare_ref: @compare_ref,
        generated_at: Time.now.iso8601,
        commit_count: commits.length,
        jira_ticket_count: jira_details.length,
        pull_request_count: pull_requests.length,
        files_changed: file_changes[:total_files],
      },
      commits: commits,
      file_changes: file_changes,
      jira_tickets: jira_details,
      pull_requests: pull_requests,
      pr_grouped_changes: grouped_changes,
    }
  end

  def call_llm(prompt, max_tokens = 1000)
    uri = URI("https://api.anthropic.com/v1/messages")
    request = Net::HTTP::Post.new(uri)
    request["Content-Type"] = "application/json"
    request["x-api-key"] = @anthropic_api_key
    request["anthropic-version"] = "2023-06-01"

    request.body = {
      model: @anthropic_model,
      max_tokens: max_tokens,
      messages: [
        {
          role: "user",
          content: prompt,
        },
      ],
    }.to_json

    http = Net::HTTP.new(uri.hostname, uri.port)
    http.use_ssl = true
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE
    http.read_timeout = 120
    response = http.request(request)

    if response.code == "200"
      result = JSON.parse(response.body)
      result["content"][0]["text"]
    else
      error("LLM API error: #{response.code}")
      error(response.body)
      raise "API error: #{response.code}"
    end
  rescue => e
    error("Failed to call LLM: #{e.message}")
    raise
  end

  def publish_grouped_changes_to_confluence(grouped_changes, context, output_path, all_jira_details)
    # Create a single timestamp for all pages in this run for uniqueness
    run_timestamp = Time.now.strftime("%Y-%m-%d %H:%M:%S")

    # Create parent page first
    parent_content = build_parent_page_content(context, grouped_changes)

    log("  Creating parent page '#{run_timestamp}' in Confluence...")

    begin
      parent_result = @confluence_client.create_page(
        title: run_timestamp,
        content: parent_content,
        parent_id: OUTPUT_PARENT_PAGE_ID,
        space_id: OUTPUT_SPACE_ID,
      )

      parent_page_id = parent_result["id"]
      parent_page_url = "#{@confluence_base_url}/wiki/spaces/SYSPROC/pages/#{parent_page_id}"
      log("    [OK] Parent page created: #{parent_page_url}")
    rescue => e
      error("    Failed to create parent page: #{e.message}")
      return
    end

    # Generate and publish each PR page (sequentially)
    grouped_changes[:pr_groups].each_with_index do |pr_group, index|
      generate_and_publish_pr_page(
        pr_group,
        parent_page_id,
        all_jira_details,
        output_path,
        index,
        grouped_changes[:pr_groups].length,
        run_timestamp,
      )
    end

    # Generate direct commits page if any exist
    if grouped_changes[:direct_commits][:commits].any?
      generate_and_publish_direct_commits_page(
        grouped_changes[:direct_commits],
        parent_page_id,
        all_jira_details,
        output_path,
        grouped_changes[:pr_groups].length,
        run_timestamp,
      )
    end

    log("")
    log("[OK] All pages published to Confluence!")
  end

  def group_commits_by_pr(commits, commit_to_pr_map)
    # Group commits by their associated PR
    pr_groups = {}
    direct_commits = []

    commits.each do |commit|
      pr_data = commit_to_pr_map[commit[:hash]]

      if pr_data
        pr_number = pr_data[:number]
        pr_groups[pr_number] ||= {
          pr: pr_data,
          commits: [],
          jira_tickets: Set.new,
        }
        pr_groups[pr_number][:commits] << commit

        # Extract Jira tickets from this commit
        jira_tickets_in_commit = extract_jira_ticket_ids_from_commit(commit)
        pr_groups[pr_number][:jira_tickets].merge(jira_tickets_in_commit)

        # Extract Jira tickets from PR branch name, title, and description
        jira_tickets_in_branch = extract_jira_ticket_ids_from_branch(pr_data[:branch])
        pr_groups[pr_number][:jira_tickets].merge(jira_tickets_in_branch)

        # Extract from PR title (case-insensitive)
        if pr_data[:title]
          title_upper = pr_data[:title].upcase
          title_tickets = title_upper.scan(JIRA_PATTERN).flatten
          pr_groups[pr_number][:jira_tickets].merge(title_tickets)
        end

        # Extract from PR body/description (case-insensitive)
        if pr_data[:description]
          body_upper = pr_data[:description].upcase
          body_tickets = body_upper.scan(JIRA_PATTERN).flatten
          pr_groups[pr_number][:jira_tickets].merge(body_tickets)
        end
      else
        direct_commits << commit
      end
    end

    # Extract Jira tickets from direct commits
    direct_jira_tickets = Set.new
    direct_commits.each do |commit|
      jira_ticket_ids = extract_jira_ticket_ids_from_commit(commit)
      direct_jira_tickets.merge(jira_ticket_ids)
    end

    # Convert sets to arrays and sort PR groups by PR number
    pr_groups_array = pr_groups.sort_by { |num, _| num }.map do |_num, data|
      {
        pr: data[:pr],
        commits: data[:commits],
        jira_tickets: data[:jira_tickets].to_a.sort,
      }
    end

    {
      pr_groups: pr_groups_array,
      direct_commits: {
        commits: direct_commits,
        jira_tickets: direct_jira_tickets.to_a.sort,
      },
    }
  end

  def extract_file_changes_for_commits(commits)
    return {
      stats: "",
      total_files: 0,
      changed_files: [],
      categorized: {},
    } if commits.empty?

    changed_files = Set.new

    commits.each do |commit|
      files_output = %x(git show --name-only --pretty=format: #{commit[:hash]} 2>/dev/null).strip
      files = files_output.split("\n").reject(&:empty?)
      changed_files.merge(files)
    end

    changed_files = changed_files.to_a.sort
    categorized = categorize_files(changed_files)

    {
      stats: "#{changed_files.length} files changed",
      total_files: changed_files.length,
      changed_files: changed_files,
      categorized: categorized,
    }
  end

  def build_pr_context(pr_group, all_jira_details)
    pr = pr_group[:pr]
    pr_commits = pr_group[:commits]

    # Extract file changes for this PR's commits
    pr_file_changes = extract_file_changes_for_commits(pr_commits)

    # Get full Jira details for tickets referenced in this PR
    pr_jira_tickets = all_jira_details.select { |t| pr_group[:jira_tickets].include?(t[:key]) }

    {
      metadata: {
        pr_number: pr[:number],
        pr_title: pr[:title],
        pr_author: pr[:author],
        commit_count: pr_commits.length,
        jira_ticket_count: pr_jira_tickets.length,
        files_changed: pr_file_changes[:total_files],
        base_ref: @base_ref,
        compare_ref: @compare_ref,
        generated_at: Time.now.iso8601,
        pull_request_count: 1,
      },
      commits: pr_commits,
      file_changes: pr_file_changes,
      jira_tickets: pr_jira_tickets,
      pull_requests: [pr],
    }
  end

  def build_direct_commits_context(direct_commits_group, all_jira_details)
    dc_commits = direct_commits_group[:commits]

    # Extract file changes for direct commits
    dc_file_changes = extract_file_changes_for_commits(dc_commits)

    # Get full Jira details for tickets referenced in direct commits
    dc_jira_tickets = all_jira_details.select { |t| direct_commits_group[:jira_tickets].include?(t[:key]) }

    {
      metadata: {
        commit_count: dc_commits.length,
        jira_ticket_count: dc_jira_tickets.length,
        files_changed: dc_file_changes[:total_files],
        base_ref: @base_ref,
        compare_ref: @compare_ref,
        generated_at: Time.now.iso8601,
        pull_request_count: 0,
      },
      commits: dc_commits,
      file_changes: dc_file_changes,
      jira_tickets: dc_jira_tickets,
      pull_requests: [],
    }
  end

  def generate_sections_for_context(context, output_path, prefix)
    section_contents = []
    section_configs = build_section_configs_from_confluence(context, @confluence_config)

    section_configs.each_with_index do |(section_name, config), index|
      log("      [#{index + 1}/#{section_configs.length}] #{config[:title]}...")

      prompt = config[:prompt_builder].call(context)
      max_tokens = config[:max_tokens] || 1000

      content = call_llm(prompt, max_tokens)

      # Write to file immediately
      index_str = config[:index]
      filename = "#{prefix}_#{index_str}_#{section_name}.md"
      filepath = File.join(output_path, filename)

      file_content = <<~MARKDOWN
        # #{config[:title]}

        *Generated: #{Time.now.iso8601}*

        ---

        #{content}
      MARKDOWN

      File.write(filepath, file_content)
      section_contents << { title: config[:title], index: index_str, content: content }
      log("        ✓ #{config[:title]} (#{content.length} chars)")
    rescue => e
      error("        [!] Error generating #{config[:title]}: #{e.message}")
      # Still write error file
      index_str = config[:index]
      filename = "#{prefix}_#{index_str}_#{section_name}.md"
      filepath = File.join(output_path, filename)
      error_content = "Error: #{e.message}"
      File.write(filepath, "# #{config[:title]}\n\n#{error_content}")
      section_contents << { title: config[:title], index: index_str, content: error_content }
    end

    section_contents
  end

  def generate_and_publish_pr_page(pr_group, parent_page_id, all_jira_details, output_path, index, total_prs, run_timestamp)
    pr = pr_group[:pr]
    page_title = "PR ##{pr[:number]}: #{pr[:title]} (#{run_timestamp})"

    log("    [#{index + 1}/#{total_prs}] Generating PR ##{pr[:number]} sections...")

    # Build PR-specific context
    pr_context = build_pr_context(pr_group, all_jira_details)

    # Generate all sections (sequentially)
    section_contents = generate_sections_for_context(pr_context, output_path, "pr_#{pr[:number]}")

    # Build and publish page
    confluence_content = build_confluence_page_content(section_contents, pr_context)

    begin
      result = @confluence_client.create_page(
        title: page_title,
        content: confluence_content,
        parent_id: parent_page_id,
        space_id: OUTPUT_SPACE_ID,
      )

      page_url = "#{@confluence_base_url}/wiki/spaces/SYSPROC/pages/#{result["id"]}"
      log("      [OK] Published: #{page_url}")
    rescue => e
      error("      Failed to publish PR ##{pr[:number]}: #{e.message}")
    end
  end

  def generate_and_publish_direct_commits_page(direct_commits_group, parent_page_id, all_jira_details, output_path, pr_count, run_timestamp)
    page_title = "Direct Commits (#{run_timestamp})"

    log("    [#{pr_count + 1}/#{pr_count + 1}] Generating Direct Commits sections...")

    # Build context for direct commits
    dc_context = build_direct_commits_context(direct_commits_group, all_jira_details)

    # Generate all sections (sequentially)
    section_contents = generate_sections_for_context(dc_context, output_path, "direct_commits")

    # Build custom content with commit links
    confluence_content = build_direct_commits_page_content(section_contents, dc_context)

    begin
      result = @confluence_client.create_page(
        title: page_title,
        content: confluence_content,
        parent_id: parent_page_id,
        space_id: OUTPUT_SPACE_ID,
      )

      page_url = "#{@confluence_base_url}/wiki/spaces/SYSPROC/pages/#{result["id"]}"
      log("      [OK] Published: #{page_url}")
    rescue => e
      error("      Failed to publish Direct Commits page: #{e.message}")
    end
  end

  def build_parent_page_content(context, grouped_changes)
    pr_bullets = grouped_changes[:pr_groups].map do |pr_group|
      pr = pr_group[:pr]
      ticket_tags = if pr_group[:jira_tickets].any?
        " " + pr_group[:jira_tickets].map { |t| "<code>#{escape_html(t)}</code>" }.join(" ")
      else
        ""
      end
      "<li><strong>PR ##{pr[:number]}</strong>: #{escape_html(pr[:title])} (by #{escape_html(pr[:author] || "Unknown")})#{ticket_tags}</li>"
    end.join("\n    ")

    direct_bullet = if grouped_changes[:direct_commits][:commits].any?
      count = grouped_changes[:direct_commits][:commits].length
      "\n    <li><strong>Direct Commits</strong>: #{count} commits not associated with a PR</li>"
    else
      ""
    end

    <<~HTML
      <p><strong>Generated:</strong> #{Time.now.iso8601}</p>
      <p><strong>Deployment:</strong> #{escape_html(context[:metadata][:compare_ref])} → #{escape_html(context[:metadata][:base_ref])}</p>
      <p><strong>Total Commits:</strong> #{context[:metadata][:commit_count]} | <strong>Pull Requests:</strong> #{grouped_changes[:pr_groups].length} | <strong>Jira Tickets:</strong> #{context[:metadata][:jira_ticket_count]}</p>
      <hr />
      <h2>Changes in this Deployment</h2>
      <ul>
        #{pr_bullets}#{direct_bullet}
      </ul>
    HTML
  end

  def build_direct_commits_page_content(section_contents, context)
    # Build direct commits page with commit links at the top
    commits = context[:commits]

    commit_links_html = if commits.any?
      commits_list = commits.map do |commit|
        commit_short = commit[:short_hash]
        subject = escape_html(commit[:subject])
        author = escape_html(commit[:author])
        date = commit[:date]

        "<li><code>#{commit_short}</code> <strong>#{subject}</strong><br /><em>#{author} (#{date})</em></li>"
      end.join("\n")

      <<~HTML
        <h2>Commits</h2>
        <p><strong>Total:</strong> #{commits.length} commits</p>
        <ul>
          #{commits_list}
        </ul>
        <hr />
      HTML
    else
      ""
    end

    # Build sections like normal page
    sections_html = section_contents.sort_by { |s| s[:index].to_s }.map do |section|
      html_content = markdown_to_confluence_storage(section[:content])

      <<~HTML
        <h2>#{escape_html(section[:title])}</h2>
        #{html_content}
      HTML
    end.join("\n\n")

    <<~HTML
      <p><strong>Generated:</strong> #{Time.now.iso8601}</p>
      <p><strong>Deployment:</strong> #{escape_html(context[:metadata][:compare_ref])} → #{escape_html(context[:metadata][:base_ref])}</p>
      <p><strong>Commits:</strong> #{context[:metadata][:commit_count]} | <strong>Jira Tickets:</strong> #{context[:metadata][:jira_ticket_count]} | <strong>Files Changed:</strong> #{context[:metadata][:files_changed]}</p>
      <hr />
      #{commit_links_html}
      #{sections_html}
    HTML
  end

  def build_confluence_page_content(section_contents, context)
    # Build Confluence storage format (XHTML-based)
    sections_html = section_contents.sort_by { |s| s[:index].to_s }.map do |section|
      # Convert markdown-like content to basic HTML
      html_content = markdown_to_confluence_storage(section[:content])

      <<~HTML
        <h2>#{escape_html(section[:title])}</h2>
        #{html_content}
      HTML
    end.join("\n\n")

    <<~HTML
      <p><strong>Generated:</strong> #{Time.now.iso8601}</p>
      <p><strong>Deployment:</strong> #{escape_html(context[:metadata][:compare_ref])} → #{escape_html(context[:metadata][:base_ref])}</p>
      <p><strong>Commits:</strong> #{context[:metadata][:commit_count]} | <strong>Jira Tickets:</strong> #{context[:metadata][:jira_ticket_count]} | <strong>Files Changed:</strong> #{context[:metadata][:files_changed]}</p>
      <hr />
      #{sections_html}
    HTML
  end

  def markdown_to_confluence_storage(markdown)
    return "<p>No content</p>" if markdown.nil? || markdown.strip.empty?

    html = markdown.dup

    # Escape HTML entities first
    html = escape_html(html)

    # Convert markdown headers (### Header -> <h3>)
    html.gsub!(/^### (.+)$/, '<h3>\1</h3>')
    html.gsub!(/^## (.+)$/, '<h4>\1</h4>')

    # Convert bold (**text** or __text__)
    html.gsub!(/\*\*(.+?)\*\*/, '<strong>\1</strong>')
    html.gsub!(/__(.+?)__/, '<strong>\1</strong>')

    # Convert italic (*text* or _text_)
    html.gsub!(/\*(.+?)\*/, '<em>\1</em>')
    html.gsub!(/_(.+?)_/, '<em>\1</em>')

    # Convert inline code (`code`)
    html.gsub!(/`([^`]+)`/, '<code>\1</code>')

    # Convert bullet lists
    lines = html.split("\n")
    in_list = false
    result_lines = []

    lines.each do |line|
      if line =~ /^[\s]*[-*]\s+(.+)$/
        unless in_list
          result_lines << "<ul>"
          in_list = true
        end
        result_lines << "<li>#{Regexp.last_match(1)}</li>"
      else
        if in_list
          result_lines << "</ul>"
          in_list = false
        end
        # Wrap non-empty lines that aren't already HTML tags in paragraphs
        result_lines << if line.strip.empty?
          ""
        elsif line.strip =~ /^<(h[2-6]|ul|li|ol|p|hr|table|tr|td|th)/
          line
        else
          "<p>#{line}</p>"
        end
      end
    end

    result_lines << "</ul>" if in_list
    result_lines.join("\n")
  end

  def escape_html(text)
    text.to_s.
      gsub("&", "&amp;").
      gsub("<", "&lt;").
      gsub(">", "&gt;").
      gsub('"', "&quot;")
  end

  def build_section_configs_from_confluence(context, confluence_config)
    sections = confluence_config["sections"] || []

    unless sections.any?
      error("No sections found in Confluence configuration")
      exit(1)
    end

    section_configs = {}
    sections.each do |section|
      key = section["key"] || section["index"]
      title = section["title"]
      index = section["index"]
      max_tokens = section["max_tokens"] || 1000
      prompt_template = section["prompt"]

      unless key && title && index && prompt_template
        error("Invalid section in Confluence config - missing required fields: #{section}")
        exit(1)
      end

      section_configs[key.to_sym] = {
        title: title,
        index: index,
        max_tokens: max_tokens,
        prompt_template: prompt_template,
        prompt_builder: ->(ctx) { build_prompt_from_template(prompt_template, ctx) },
      }
    end

    section_configs
  end

  def build_prompt_from_template(template, context)
    # Build comprehensive context to include with the prompt
    full_context = build_deployment_context_for_prompt(context)

    # Template gets full context prepended, then any variable substitutions
    prompt = full_context + "\n\n" + template

    # Replace common placeholders (for backward compatibility)
    prompt.gsub!("{{commit_count}}", context[:metadata][:commit_count].to_s)
    prompt.gsub!("{{jira_count}}", context[:metadata][:jira_ticket_count].to_s)
    prompt.gsub!("{{compare_ref}}", context[:metadata][:compare_ref])
    prompt.gsub!("{{base_ref}}", context[:metadata][:base_ref])
    prompt.gsub!("{{files_changed}}", context[:metadata][:files_changed].to_s)

    prompt
  end

  def build_deployment_context_for_prompt(context)
    <<~CONTEXT
      # Deployment Context

      **Deployment Details:**
      - Deploying: #{context[:metadata][:compare_ref]} → #{context[:metadata][:base_ref]}
      - Commits: #{context[:metadata][:commit_count]}
      - Jira Tickets: #{context[:metadata][:jira_ticket_count]}
      - Pull Requests: #{context[:metadata][:pull_request_count]}
      - Files Changed: #{context[:metadata][:files_changed]}
      - Generated: #{context[:metadata][:generated_at]}

      ## Commits

      #{format_commits_for_prompt(context[:commits])}

      ## File Changes Summary

      #{context[:file_changes][:stats]}

      ## Changed Files by Category

      #{format_file_categories(context[:file_changes][:categorized])}

      ## Associated Jira Tickets

      #{format_jira_for_prompt(context[:jira_tickets])}

      ## Associated Pull Requests

      #{format_prs_for_prompt(context[:pull_requests])}

      ---
    CONTEXT
  end

  def format_commits_for_prompt(commits)
    if commits.empty?
      return "No commits found in this range."
    end

    commits.map do |c|
      body_preview = c[:body].empty? ? "" : "\n  #{c[:body].lines.first&.strip}"
      "- `#{c[:short_hash]}` **#{c[:subject]}**#{body_preview}\n  _#{c[:author]} (#{c[:date]})_"
    end.join("\n\n")
  end

  def format_file_categories(categorized)
    return "No files changed." if categorized.empty?

    categorized.map do |category, files|
      "**#{category.to_s.capitalize}** (#{files.length}):\n" +
        files.map { |f| "  - `#{f}`" }.join("\n")
    end.join("\n\n")
  end

  def format_jira_for_prompt(jira_tickets)
    return "No Jira tickets referenced in commits." if jira_tickets.empty?

    jira_tickets.map do |ticket|
      if ticket[:error]
        "- **#{ticket[:key]}**: [!] Could not fetch details (#{ticket[:error]})"
      else
        description_preview = ticket[:description]&.strip&.lines&.first(3)&.join(" ")&.strip
        description_preview = description_preview&.slice(0, 200) if description_preview && description_preview.length > 200

        <<~TICKET.strip
          - **#{ticket[:key]}**: #{ticket[:summary]}
            - Type: #{ticket[:type]} | Status: #{ticket[:status]} | Priority: #{ticket[:priority]}
            - Assignee: #{ticket[:assignee]}
            - Components: #{ticket[:components]&.any? ? ticket[:components].join(", ") : "None"}
            - Labels: #{ticket[:labels]&.any? ? ticket[:labels].join(", ") : "None"}
            - Description: #{description_preview || "No description provided"}
        TICKET
      end
    end.join("\n\n")
  end

  def format_prs_for_prompt(pull_requests)
    return "No pull requests found." if pull_requests.empty?

    pull_requests.map do |pr|
      description_text = if pr[:description]&.include?("Error") || pr[:description]&.include?("Unable")
        pr[:description]
      else
        pr[:description]&.strip&.lines&.first(10)&.join("\n")&.strip || "No description provided"
      end

      <<~PR.strip
        - **##{pr[:number]}**: #{pr[:title]}
          - Author: #{pr[:author] || "Unknown"}
          - Commit: #{pr[:commit_hash] || "N/A"}
          - Description: #{description_text}
      PR
    end.join("\n\n")
  end

  def log(message)
    puts message
  end

  def error(message)
    warn("[ERROR] #{message}")
  end
end

def main
  options = {}

  parser = OptionParser.new do |opts|
    opts.banner = "Usage: #{File.basename($0)} [options]"
    opts.separator("")
    opts.separator("Generate a compliance-focused deployment summary by comparing two Git references.")
    opts.separator("References can be branch names or commit SHAs.")
    opts.separator("")
    opts.separator("Required Environment Variables:")
    opts.separator("  RN_JIRA_BASE_URL           - Your Jira instance URL (e.g., https://yourcompany.atlassian.net)")
    opts.separator("  RN_JIRA_CLOUD_ID           - Your Atlassian Cloud ID (required for scoped API tokens)")
    opts.separator("  RN_JIRA_EMAIL              - Atlassian account email")
    opts.separator("  RN_ATLASSIAN_API_TOKEN     - Atlassian API token (used for both Jira and Confluence)")
    opts.separator("  RN_ANTHROPIC_API_KEY       - Anthropic API key for Claude")
    opts.separator("  RN_CONFLUENCE_BASE_URL     - Confluence instance URL (e.g., https://company.atlassian.net)")
    opts.separator("")
    opts.separator("Confluence Configuration:")
    opts.separator("  Prompt configuration is loaded from page ID #{DeploymentSummaryGenerator::PROMPT_CONFIG_PAGE_ID}")
    opts.separator("  Output is published under parent page ID #{DeploymentSummaryGenerator::OUTPUT_PARENT_PAGE_ID}")
    opts.separator("")
    opts.separator("Optional Environment Variables:")
    opts.separator("  RN_ANTHROPIC_MODEL         - Anthropic model to use (default: claude-haiku-4-5)")
    opts.separator("")
    opts.separator("Options:")

    opts.on("-b", "--base REF", "Base reference (branch name or commit SHA, default: production)") do |ref|
      options[:base_ref] = ref
    end

    opts.on("-c", "--compare REF", "Compare reference (branch name or commit SHA, default: main)") do |ref|
      options[:compare_ref] = ref
    end

    opts.on("-o", "--output DIR", "Output directory (default: current directory)") do |dir|
      options[:output_dir] = dir
    end

    opts.on("-v", "--verbose", "Verbose output") do
      options[:verbose] = true
    end

    opts.on("-h", "--help", "Show this help message") do
      puts opts
      exit
    end
  end

  begin
    parser.parse!
  rescue OptionParser::InvalidOption => e
    puts e
    puts parser
    exit(1)
  end

  generator = DeploymentSummaryGenerator.new(options)
  generator.generate
end

if __FILE__ == $PROGRAM_NAME
  main
end
