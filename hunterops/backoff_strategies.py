"""Backoff Strategies for Rate Limiting - PASSO 5

Strategies for handling rate-limited requests:
1. Exponential backoff (2^n seconds) - Recommended for distributed systems
2. Linear backoff (n seconds) - For predictable delays
3. Fixed backoff (constant) - Simple, deterministic
4. Jittered backoff - Prevents thundering herd
"""

import asyncio
import random
import logging
from enum import Enum
from typing import Optional, Callable, Awaitable, Any
from dataclasses import dataclass
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


class BackoffStrategy(str, Enum):
    """Backoff strategy for rate-limited requests."""
    EXPONENTIAL = "EXPONENTIAL"        # 2^n seconds
    LINEAR = "LINEAR"                  # n seconds
    FIXED = "FIXED"                    # constant delay
    EXPONENTIAL_JITTER = "EXPONENTIAL_JITTER"  # 2^n + random
    LINEAR_JITTER = "LINEAR_JITTER"    # n + random


@dataclass
class BackoffConfig:
    """Configuration for backoff strategy."""
    strategy: BackoffStrategy
    initial_delay: float = 1.0          # First backoff wait (seconds)
    max_delay: float = 300.0            # Maximum wait (5 minutes)
    max_retries: int = 5                # Give up after N retries
    jitter_factor: float = 0.1          # 0.0-1.0 for jitter amount


class BackoffCalculator:
    """Calculate backoff delay based on strategy."""

    @staticmethod
    def _strategy_key(strategy: Any) -> str:
        """Normalize strategy values across enum types/modules."""
        if hasattr(strategy, "value"):
            return str(getattr(strategy, "value")).strip().upper()
        raw = str(strategy).strip()
        if "." in raw:
            raw = raw.split(".")[-1]
        return raw.upper()

    @staticmethod
    def calculate_exponential(
        attempt: int,
        initial_delay: float = 1.0,
        max_delay: float = 300.0
    ) -> float:
        """Exponential backoff: 2^n seconds.
        
        Attempt 1: 1s
        Attempt 2: 2s
        Attempt 3: 4s
        Attempt 4: 8s
        Attempt 5: 16s
        ...caps at max_delay
        """
        delay = initial_delay * (2 ** (attempt - 1))
        return min(delay, max_delay)

    @staticmethod
    def calculate_linear(
        attempt: int,
        initial_delay: float = 1.0,
        max_delay: float = 300.0
    ) -> float:
        """Linear backoff: n seconds.
        
        Attempt 1: 1s
        Attempt 2: 2s
        Attempt 3: 3s
        Attempt 4: 4s
        ...caps at max_delay
        """
        delay = initial_delay * attempt
        return min(delay, max_delay)

    @staticmethod
    def calculate_fixed(
        attempt: int,
        fixed_delay: float = 1.0
    ) -> float:
        """Fixed backoff: constant delay.
        
        Attempt 1: 1s
        Attempt 2: 1s
        Attempt 3: 1s
        ...
        """
        return fixed_delay

    @staticmethod
    def add_jitter(
        delay: float,
        jitter_factor: float = 0.1
    ) -> float:
        """Add random jitter to delay (prevents thundering herd).
        
        jitter_factor=0.1 means ±10% variation
        """
        if jitter_factor == 0:
            return delay

        jitter = delay * jitter_factor
        return delay + random.uniform(-jitter, jitter)

    @staticmethod
    def calculate(
        attempt: int,
        config: BackoffConfig
    ) -> float:
        """Calculate backoff delay for attempt number.
        
        Args:
            attempt: Attempt number (1-based)
            config: Backoff configuration
            
        Returns:
            Delay in seconds
        """
        strategy_key = BackoffCalculator._strategy_key(config.strategy)

        if strategy_key == BackoffStrategy.EXPONENTIAL.value:
            delay = BackoffCalculator.calculate_exponential(
                attempt,
                config.initial_delay,
                config.max_delay
            )
        elif strategy_key == BackoffStrategy.LINEAR.value:
            delay = BackoffCalculator.calculate_linear(
                attempt,
                config.initial_delay,
                config.max_delay
            )
        elif strategy_key == BackoffStrategy.FIXED.value:
            delay = BackoffCalculator.calculate_fixed(
                attempt,
                config.initial_delay
            )
        elif strategy_key == BackoffStrategy.EXPONENTIAL_JITTER.value:
            delay = BackoffCalculator.calculate_exponential(
                attempt,
                config.initial_delay,
                config.max_delay
            )
            delay = BackoffCalculator.add_jitter(delay, config.jitter_factor)
        elif strategy_key == BackoffStrategy.LINEAR_JITTER.value:
            delay = BackoffCalculator.calculate_linear(
                attempt,
                config.initial_delay,
                config.max_delay
            )
            delay = BackoffCalculator.add_jitter(delay, config.jitter_factor)
        else:
            delay = config.initial_delay

        return max(0.0, min(delay, config.max_delay))


class BackoffExecutor:
    """Execute function with automatic backoff retry."""

    @staticmethod
    async def retry_with_backoff(
        coro_func: Callable[[], Awaitable[Any]],
        config: BackoffConfig
    ) -> Any:
        """Retry coroutine with backoff.
        
        Args:
            coro_func: Async function to retry (returns coroutine)
            config: Backoff configuration
            
        Returns:
            Result from successful attempt
            
        Raises:
            Exception from final failed attempt
        """
        last_exception = None
        total_attempts = max(1, int(config.max_retries) + 1)

        for attempt in range(1, total_attempts + 1):
            try:
                logger.debug(f"Attempt {attempt}/{total_attempts}")
                return await coro_func()
            except Exception as e:
                last_exception = e

                if attempt >= total_attempts:
                    break

                # Calculate backoff
                delay = BackoffCalculator.calculate(attempt, config)
                logger.warning(
                    f"Attempt {attempt} failed: {e}. "
                    f"Retrying in {delay:.1f}s..."
                )

                # Wait before retry
                await asyncio.sleep(delay)

        # All retries exhausted
        logger.error(f"All {config.max_retries} attempts failed")
        raise last_exception if last_exception else RuntimeError("All retries failed")

    @staticmethod
    def retry_sync(
        func: Callable[[], Any],
        config: BackoffConfig
    ) -> Any:
        """Retry synchronous function with backoff.
        
        Args:
            func: Synchronous function to retry
            config: Backoff configuration
            
        Returns:
            Result from successful attempt
            
        Raises:
            Exception from final failed attempt
        """
        last_exception = None
        total_attempts = max(1, int(config.max_retries) + 1)

        for attempt in range(1, total_attempts + 1):
            try:
                logger.debug(f"Attempt {attempt}/{total_attempts}")
                return func()
            except Exception as e:
                last_exception = e

                if attempt >= total_attempts:
                    break

                # Calculate backoff
                delay = BackoffCalculator.calculate(attempt, config)
                logger.warning(
                    f"Attempt {attempt} failed: {e}. "
                    f"Retrying in {delay:.1f}s..."
                )

                # Wait before retry
                import time
                time.sleep(delay)

        # All retries exhausted
        logger.error(f"All {config.max_retries} attempts failed")
        raise last_exception if last_exception else RuntimeError("All retries failed")


# Predefined configurations

BACKOFF_CONFIG_AGGRESSIVE = BackoffConfig(
    strategy=BackoffStrategy.EXPONENTIAL,
    initial_delay=0.5,
    max_delay=60.0,
    max_retries=5
)

BACKOFF_CONFIG_CONSERVATIVE = BackoffConfig(
    strategy=BackoffStrategy.LINEAR_JITTER,
    initial_delay=2.0,
    max_delay=120.0,
    max_retries=10
)

BACKOFF_CONFIG_IMMEDIATE = BackoffConfig(
    strategy=BackoffStrategy.FIXED,
    initial_delay=0.1,
    max_delay=1.0,
    max_retries=3
)

__all__ = [
    'BackoffStrategy',
    'BackoffConfig',
    'BackoffCalculator',
    'BackoffExecutor',
    'BACKOFF_CONFIG_AGGRESSIVE',
    'BACKOFF_CONFIG_CONSERVATIVE',
    'BACKOFF_CONFIG_IMMEDIATE',
]
