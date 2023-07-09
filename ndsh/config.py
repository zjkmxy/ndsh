from dataclasses import dataclass, field
from ndn.encoding import FormalName, Name


@dataclass
class Config:
    app_prefix: FormalName = field(default_factory=lambda: Name.from_str('/ndsh/test'))
    stream_buffer_size: int = 4000


SystemConfig = Config()
