import time
from plyer import notification 

if __name__ == "__main__":
    notification.notify(
        title="Please drink water!",
        message="Daily water needs average 2.7 to 3.7 litres from all food and drinks, though individual requirements vary based on activity and health.💧",
        # app_icon="D:\L_Mahesh\Prakhar\Programming\water-glass.icon", 
        timeout=10
    )
    time.sleep(10)