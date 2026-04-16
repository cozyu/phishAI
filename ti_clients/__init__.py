from .virustotal import VirusTotalClient
from .urlscan import URLScanClient
from .criminalip import CriminalIPClient
from .censys import CensysClient

ALL_CLIENTS = [VirusTotalClient, URLScanClient, CriminalIPClient, CensysClient]
