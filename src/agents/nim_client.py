"""NVIDIA NIM client for LLM inference."""

from typing import Any, Dict, List, Optional

import structlog
from openai import AsyncOpenAI
from langchain_openai import ChatOpenAI

from src.config import Settings, NvidiaConfig


logger = structlog.get_logger()


class NIMClient:
    """
    Client for NVIDIA NIM API.

    Uses the OpenAI-compatible API format for interacting with
    NVIDIA's inference microservices.
    """

    def __init__(self, config: NvidiaConfig):
        self._config = config
        self._client = AsyncOpenAI(
            base_url=config.base_url,
            api_key=config.api_key,
            timeout=config.timeout,
        )

    async def chat(
        self,
        messages: List[Dict[str, str]],
        model: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        tools: Optional[List[Dict]] = None,
        tool_choice: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Send a chat completion request.

        Args:
            messages: List of message dicts with 'role' and 'content'
            model: Model to use (defaults to config model)
            temperature: Sampling temperature
            max_tokens: Maximum tokens to generate
            tools: List of tool definitions for function calling
            tool_choice: How to handle tool calls ('auto', 'none', or specific tool)

        Returns:
            API response dictionary
        """
        model = model or self._config.model
        temperature = temperature if temperature is not None else self._config.temperature
        max_tokens = max_tokens or self._config.max_tokens

        logger.debug(
            "Sending chat request to NIM",
            model=model,
            message_count=len(messages),
            has_tools=tools is not None,
        )

        try:
            kwargs = {
                "model": model,
                "messages": messages,
                "temperature": temperature,
                "max_tokens": max_tokens,
            }

            if tools:
                kwargs["tools"] = tools
            if tool_choice:
                kwargs["tool_choice"] = tool_choice

            response = await self._client.chat.completions.create(**kwargs)

            logger.debug(
                "NIM response received",
                model=model,
                finish_reason=response.choices[0].finish_reason,
                usage=response.usage.model_dump() if response.usage else None,
            )

            return {
                "id": response.id,
                "model": response.model,
                "choices": [
                    {
                        "index": c.index,
                        "message": {
                            "role": c.message.role,
                            "content": c.message.content,
                            "tool_calls": [
                                {
                                    "id": tc.id,
                                    "type": tc.type,
                                    "function": {
                                        "name": tc.function.name,
                                        "arguments": tc.function.arguments,
                                    },
                                }
                                for tc in (c.message.tool_calls or [])
                            ] if c.message.tool_calls else None,
                        },
                        "finish_reason": c.finish_reason,
                    }
                    for c in response.choices
                ],
                "usage": response.usage.model_dump() if response.usage else None,
            }

        except Exception as e:
            logger.error(
                "NIM request failed",
                model=model,
                error=str(e),
            )
            raise

    async def complete(
        self,
        prompt: str,
        model: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
    ) -> str:
        """
        Simple completion interface.

        Args:
            prompt: The prompt to complete
            model: Model to use
            temperature: Sampling temperature
            max_tokens: Maximum tokens

        Returns:
            The generated text
        """
        messages = [{"role": "user", "content": prompt}]
        response = await self.chat(
            messages=messages,
            model=model,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        return response["choices"][0]["message"]["content"]


def create_langchain_llm(config: NvidiaConfig) -> ChatOpenAI:
    """
    Create a LangChain ChatOpenAI instance configured for NVIDIA NIM.

    This is used by CrewAI agents for LLM calls.
    """
    return ChatOpenAI(
        base_url=config.base_url,
        api_key=config.api_key,
        model=config.model,
        temperature=config.temperature,
        max_tokens=config.max_tokens,
        timeout=config.timeout,
    )


# Global NIM client instance
_nim_client: Optional[NIMClient] = None


def get_nim_client(settings: Optional[Settings] = None) -> NIMClient:
    """Get the global NIM client instance."""
    global _nim_client
    if _nim_client is None:
        if settings is None:
            from src.config import get_settings
            settings = get_settings()
        _nim_client = NIMClient(settings.nvidia)
    return _nim_client


def reset_nim_client():
    """Reset the global NIM client (for testing)."""
    global _nim_client
    _nim_client = None
