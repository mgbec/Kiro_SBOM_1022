"""Streaming utilities for the SBOM Security Agent."""

import asyncio
from typing import AsyncGenerator, Optional


class StreamingQueue:
    """
    Async queue for streaming responses to users.
    
    This follows the same pattern as the reference implementation
    for handling streaming responses in AgentCore.
    """
    
    def __init__(self):
        self._queue: asyncio.Queue = asyncio.Queue()
        self._finished: bool = False
    
    async def put(self, item: str) -> None:
        """
        Add an item to the streaming queue.
        
        Args:
            item: The message to add to the stream
        """
        if not self._finished:
            await self._queue.put(item)
    
    async def finish(self) -> None:
        """Mark the stream as finished and add sentinel value."""
        self._finished = True
        await self._queue.put(None)
    
    async def stream(self) -> AsyncGenerator[str, None]:
        """
        Stream items from the queue until finished.
        
        Yields:
            str: Messages from the queue
        """
        while True:
            try:
                item = await self._queue.get()
                if item is None and self._finished:
                    break
                if item is not None:
                    yield item
            except asyncio.CancelledError:
                break
    
    def is_finished(self) -> bool:
        """Check if the stream is finished."""
        return self._finished


class ProgressTracker:
    """Track and report progress of long-running operations."""
    
    def __init__(self, queue: StreamingQueue, total_steps: int = 100):
        self.queue = queue
        self.total_steps = total_steps
        self.current_step = 0
        self.current_operation = ""
    
    async def update(self, step: int, operation: str = "") -> None:
        """
        Update progress and send to stream.
        
        Args:
            step: Current step number
            operation: Description of current operation
        """
        self.current_step = min(step, self.total_steps)
        if operation:
            self.current_operation = operation
        
        percentage = (self.current_step / self.total_steps) * 100
        progress_msg = f"Progress: {percentage:.1f}% - {self.current_operation}"
        await self.queue.put(progress_msg)
    
    async def increment(self, operation: str = "") -> None:
        """
        Increment progress by one step.
        
        Args:
            operation: Description of current operation
        """
        await self.update(self.current_step + 1, operation)
    
    async def complete(self, message: str = "Operation completed") -> None:
        """
        Mark operation as complete.
        
        Args:
            message: Completion message
        """
        await self.update(self.total_steps, message)


async def stream_with_error_handling(
    operation_func,
    queue: StreamingQueue,
    error_prefix: str = "Error"
) -> None:
    """
    Execute an operation with error handling and streaming.
    
    Args:
        operation_func: Async function to execute
        queue: Streaming queue for messages
        error_prefix: Prefix for error messages
    """
    try:
        await operation_func()
    except Exception as e:
        error_msg = f"{error_prefix}: {str(e)}"
        await queue.put(error_msg)
        print(f"Operation failed: {e}")
    finally:
        await queue.finish()