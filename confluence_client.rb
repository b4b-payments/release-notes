require "net/http"
require "uri"
require "json"
require "yaml"
require "base64"

class ConfluenceClient
  def initialize(base_url:, api_token:, email:, page_id: nil, page_title: nil)
    @base_url = base_url
    @api_token = api_token
    @email = email
    @page_id = page_id
    @page_title = page_title
    @auth_header = "Basic #{Base64.strict_encode64("#{@email}:#{@api_token}")}"
  end

  def fetch_config(format: :yaml)
    unless @page_id || @page_title
      raise ArgumentError, "Either page_id or page_title must be provided"
    end

    page_id = @page_id || find_page_id(@page_title)
    content = fetch_page_content(page_id)

    case format
    when :yaml
      parse_yaml_from_content(content)
    when :json
      parse_json_from_content(content)
    else
      raise ArgumentError, "Unsupported format: #{format}. Use :yaml or :json"
    end
  end

  def fetch_config_from_page(page_id, format: :yaml)
    content = fetch_page_content(page_id)

    case format
    when :yaml
      parse_yaml_from_content(content)
    when :json
      parse_json_from_content(content)
    else
      raise ArgumentError, "Unsupported format: #{format}. Use :yaml or :json"
    end
  end

  def create_page(title:, content:, parent_id:, space_id: nil)
    # Determine space ID from parent if not provided
    space_id ||= get_space_key_from_page(parent_id)

    uri = URI("#{@base_url}/wiki/api/v2/pages")

    body = {
      spaceId: space_id.to_s,
      status: "current",
      title: title,
      parentId: parent_id.to_s,
      body: {
        representation: "storage",
        value: content,
      },
    }

    request = Net::HTTP::Post.new(uri)
    request["Authorization"] = @auth_header
    request["Accept"] = "application/json"
    request["Content-Type"] = "application/json"
    request.body = body.to_json

    response = make_request(uri, request)
    JSON.parse(response.body)
  end

  def get_space_key_from_page(page_id)
    uri = URI("#{@base_url}/wiki/api/v2/pages/#{page_id}")

    request = Net::HTTP::Get.new(uri)
    request["Authorization"] = @auth_header
    request["Accept"] = "application/json"

    response = make_request(uri, request)
    data = JSON.parse(response.body)
    data["spaceId"]
  end

  def get_parent_id_from_page(page_id)
    uri = URI("#{@base_url}/wiki/api/v2/pages/#{page_id}")

    request = Net::HTTP::Get.new(uri)
    request["Authorization"] = @auth_header
    request["Accept"] = "application/json"

    response = make_request(uri, request)
    data = JSON.parse(response.body)
    data["parentId"]
  end

  private

  def find_page_id(title)
    uri = URI("#{@base_url}/wiki/api/v2/pages")
    uri.query = URI.encode_www_form(
      "type" => "page",
      "title" => title,
      "limit" => 1,
    )

    request = Net::HTTP::Get.new(uri)
    request["Authorization"] = @auth_header
    request["Accept"] = "application/json"

    response = make_request(uri, request)
    data = JSON.parse(response.body)

    if data["results"].empty?
      raise "Confluence page '#{title}' not found"
    end

    data["results"][0]["id"]
  end

  def fetch_page_content(page_id)
    uri = URI("#{@base_url}/wiki/api/v2/pages/#{page_id}")
    uri.query = URI.encode_www_form("body-format" => "storage")

    request = Net::HTTP::Get.new(uri)
    request["Authorization"] = @auth_header
    request["Accept"] = "application/json"

    response = make_request(uri, request)
    data = JSON.parse(response.body)

    data["body"]["storage"]["value"]
  end

  def parse_json_from_content(html_content)
    # Extract JSON from code block
    # Confluence stores code blocks with <ac:structured-macro name="code">
    # We look for the JSON content between CDATA tags

    # Match code block content
    json_match = html_content.match(%r{<ac:plain-text-body><!\[CDATA\[(.*?)\]\]></ac:plain-text-body>}m)

    unless json_match
      raise "No JSON configuration found in Confluence page. Expected a code block with JSON content."
    end

    json_content = json_match[1].strip

    # JSON.parse handles actual newlines in multi-line strings fine
    # Just pass it through as-is
    JSON.parse(json_content)
  rescue JSON::ParserError => e
    raise "Invalid JSON in Confluence page: #{e.message}\n\nHint: Check that all quotes are properly closed and colons are followed by spaces."
  end

  def parse_yaml_from_content(html_content)
    # Extract YAML from code block
    # Confluence stores code blocks with <ac:structured-macro name="code">
    # We look for the YAML content between CDATA tags

    # Match code block content
    yaml_match = html_content.match(%r{<ac:plain-text-body><!\[CDATA\[(.*?)\]\]></ac:plain-text-body>}m)

    unless yaml_match
      raise "No YAML configuration found in Confluence page. Expected a code block with YAML content."
    end

    yaml_content = yaml_match[1].strip

    YAML.safe_load(yaml_content, permitted_classes: [], permitted_symbols: [], aliases: true)
  rescue Psych::SyntaxError => e
    raise "Invalid YAML in Confluence page: #{e.message}\n\nHint: Check indentation and ensure colons are followed by spaces."
  end

  def make_request(uri, request)
    http = Net::HTTP.new(uri.hostname, uri.port)
    http.use_ssl = true
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE

    response = http.request(request)

    unless response.code =~ /^2\d{2}$/
      raise "Confluence API error (#{response.code}): #{response.body}"
    end

    response
  end
end
