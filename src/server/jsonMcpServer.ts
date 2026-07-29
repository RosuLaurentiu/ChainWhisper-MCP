import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  GetPromptRequestSchema,
  ListPromptsRequestSchema,
  ListResourcesRequestSchema,
  ListToolsRequestSchema,
  ReadResourceRequestSchema,
  type ToolAnnotations
} from '@modelcontextprotocol/sdk/types.js';

import { assertNoSensitiveMaterial, redactError } from '../shared/index.js';

export interface JsonMcpTool {
  name: string;
  title?: string;
  description: string;
  inputSchema: Record<string, unknown>;
  annotations?: ToolAnnotations;
  allowSensitiveOutput?: boolean;
  execute(input: Record<string, unknown>): Promise<unknown>;
}

export interface JsonMcpResource {
  uri: string;
  name: string;
  title?: string;
  description?: string;
  mimeType?: string;
  read(): Promise<string> | string;
}

export interface JsonMcpPrompt {
  name: string;
  title?: string;
  description?: string;
  arguments?: Array<{
    name: string;
    description?: string;
    required?: boolean;
  }>;
  render(args: Record<string, string>): Promise<string> | string;
}

export interface JsonMcpServerDefinition {
  name: string;
  version: string;
  instructions: string;
  tools: JsonMcpTool[];
  resources?: JsonMcpResource[];
  prompts?: JsonMcpPrompt[];
}

const jsonText = (value: unknown): string =>
  JSON.stringify(
    value,
    (_key, entry) => (typeof entry === 'bigint' ? entry.toString() : entry),
    2
  );

export const createJsonMcpServer = (definition: JsonMcpServerDefinition): Server => {
  const server = new Server(
    {
      name: definition.name,
      version: definition.version
    },
    {
      capabilities: {
        tools: {},
        resources: {},
        prompts: {}
      },
      instructions: definition.instructions
    }
  );
  const tools = new Map(definition.tools.map((tool) => [tool.name, tool] as const));
  const resources = new Map((definition.resources ?? []).map((resource) => [resource.uri, resource] as const));
  const prompts = new Map((definition.prompts ?? []).map((prompt) => [prompt.name, prompt] as const));

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: definition.tools.map((tool) => ({
      name: tool.name,
      ...(tool.title ? { title: tool.title } : {}),
      description: tool.description,
      inputSchema: tool.inputSchema,
      ...(tool.annotations ? { annotations: tool.annotations } : {})
    }))
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const tool = tools.get(request.params.name);
    if (!tool) {
      return {
        isError: true,
        content: [{ type: 'text', text: `Unknown ChainWhisper tool: ${request.params.name}.` }]
      };
    }
    try {
      const input =
        request.params.arguments && typeof request.params.arguments === 'object'
          ? request.params.arguments
          : {};
      const result = await tool.execute(input);
      if (!tool.allowSensitiveOutput) {
        assertNoSensitiveMaterial(result, `${tool.name} result`);
      }
      return {
        content: [{ type: 'text', text: jsonText(result) }]
      };
    } catch (error) {
      return {
        isError: true,
        content: [{ type: 'text', text: redactError(error) }]
      };
    }
  });

  server.setRequestHandler(ListResourcesRequestSchema, async () => ({
    resources: [...resources.values()].map((resource) => ({
      uri: resource.uri,
      name: resource.name,
      ...(resource.title ? { title: resource.title } : {}),
      ...(resource.description ? { description: resource.description } : {}),
      mimeType: resource.mimeType ?? 'application/json'
    }))
  }));

  server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
    const resource = resources.get(request.params.uri);
    if (!resource) {
      throw new Error(`Unknown ChainWhisper resource: ${request.params.uri}.`);
    }
    return {
      contents: [
        {
          uri: resource.uri,
          mimeType: resource.mimeType ?? 'application/json',
          text: await resource.read()
        }
      ]
    };
  });

  server.setRequestHandler(ListPromptsRequestSchema, async () => ({
    prompts: [...prompts.values()].map((prompt) => ({
      name: prompt.name,
      ...(prompt.title ? { title: prompt.title } : {}),
      ...(prompt.description ? { description: prompt.description } : {}),
      ...(prompt.arguments ? { arguments: prompt.arguments } : {})
    }))
  }));

  server.setRequestHandler(GetPromptRequestSchema, async (request) => {
    const prompt = prompts.get(request.params.name);
    if (!prompt) {
      throw new Error(`Unknown ChainWhisper prompt: ${request.params.name}.`);
    }
    const args = Object.fromEntries(
      Object.entries(request.params.arguments ?? {}).map(([key, value]) => [key, String(value)])
    );
    return {
      description: prompt.description,
      messages: [
        {
          role: 'user',
          content: {
            type: 'text',
            text: await prompt.render(args)
          }
        }
      ]
    };
  });

  return server;
};

export const connectStdioMcpServer = async (server: Server): Promise<void> => {
  const existingOnClose = server.onclose;
  let resolveClosed: (() => void) | undefined;
  const closed = new Promise<void>((resolve) => {
    resolveClosed = resolve;
  });
  server.onclose = () => {
    try {
      existingOnClose?.();
    } finally {
      resolveClosed?.();
    }
  };
  await server.connect(new StdioServerTransport());
  await closed;
};

export const writeFatalMcpError = (
  error: unknown,
  serverName = 'chainwhisper-mcp'
): void => {
  process.stderr.write(`[${serverName}] ${redactError(error)}\n`);
};
