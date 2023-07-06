from dataclasses import dataclass


@dataclass
class Config:
    stream_buffer_size: int = 1000


SystemConfig = Config()
