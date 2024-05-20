from dataclasses import dataclass, field
from cereal import car
from panda.python import uds
from openpilot.selfdrive.car import AngleRateLimit, CarSpecs, DbcDict, PlatformConfig, Platforms, dbc_dict
from openpilot.selfdrive.car.docs_definitions import CarDocs, CarHarness, CarParts
from openpilot.selfdrive.car.fw_query_definitions import FwQueryConfig, Request, StdQueries
Ecu = car.CarParams.Ecu

class CarControllerParams:
    ANGLE_RATE_LIMIT_UP = AngleRateLimit(speed_bp=[0.0, 5.0, 15.0], angle_v=[5.0, 0.8, 0.15])
    ANGLE_RATE_LIMIT_DOWN = AngleRateLimit(speed_bp=[0.0, 5.0, 15.0], angle_v=[5.0, 3.5, 0.4])
    LKAS_MAX_TORQUE = 1
    STEER_THRESHOLD = 1.0

    def __init__(self, CP):
        pass

@dataclass
class NissanCarDocs(CarDocs):
    package: str = 'ProPILOT Assist'
    car_parts: CarParts = field(default_factory=CarParts.common([CarHarness.nissan_a]))

@dataclass(frozen=True)
class NissanCarSpecs(CarSpecs):
    centerToFrontRatio: float = 0.44
    steerRatio: float = 17.0

@dataclass
class NissanPlatformConfig(PlatformConfig):
    dbc_dict: DbcDict = field(default_factory=lambda : dbc_dict('nissan_x_trail_2017_generated', None))

class CAR(Platforms):
    NISSAN_XTRAIL = NissanPlatformConfig([NissanCarDocs('Nissan X-Trail 2017')], NissanCarSpecs(mass=1610, wheelbase=2.705))
    NISSAN_LEAF = NissanPlatformConfig([NissanCarDocs('Nissan Leaf 2018-23', video_link='https://youtu.be/vaMbtAh_0cY')], NissanCarSpecs(mass=1610, wheelbase=2.705), dbc_dict('nissan_leaf_2018_generated', None))
    NISSAN_LEAF_IC = NISSAN_LEAF.override(car_docs=[])
    NISSAN_ROGUE = NissanPlatformConfig([NissanCarDocs('Nissan Rogue 2018-20')], NissanCarSpecs(mass=1610, wheelbase=2.705))
    NISSAN_ALTIMA = NissanPlatformConfig([NissanCarDocs('Nissan Altima 2019-20', car_parts=CarParts.common([CarHarness.nissan_b]))], NissanCarSpecs(mass=1492, wheelbase=2.824))
DBC = CAR.create_dbc_map()
NISSAN_DIAGNOSTIC_REQUEST_KWP = bytes([uds.SERVICE_TYPE.DIAGNOSTIC_SESSION_CONTROL, 129])
NISSAN_DIAGNOSTIC_RESPONSE_KWP = bytes([uds.SERVICE_TYPE.DIAGNOSTIC_SESSION_CONTROL + 64, 129])
NISSAN_DIAGNOSTIC_REQUEST_KWP_2 = bytes([uds.SERVICE_TYPE.DIAGNOSTIC_SESSION_CONTROL, 218])
NISSAN_DIAGNOSTIC_RESPONSE_KWP_2 = bytes([uds.SERVICE_TYPE.DIAGNOSTIC_SESSION_CONTROL + 64, 218])
NISSAN_VERSION_REQUEST_KWP = b'!\x83'
NISSAN_VERSION_RESPONSE_KWP = b'a\x83'
NISSAN_RX_OFFSET = 32
FW_QUERY_CONFIG = FwQueryConfig(requests=[])
