from django.http import JsonResponse, HttpResponse
import logging # logging 모듈 임포트

# 로거 설정 (settings.py에 LOGGING 설정이 없다면 기본 로거 사용)
logger = logging.getLogger(__name__)

def health_check(request):
    logger.info("Health check endpoint called!") # 헬스 체크 로그 추가
    return HttpResponse("OK")

def get_traffic_data(request):
    # --- 로그 추가 ---
    logger.info("get_traffic_data function called!") 
    # ---------------
    
    data = {
        "status": "success",
        "message": "Traffic data API endpoint reached!"
    }
    
    # --- 로그 추가 ---
    logger.info(f"Returning JSON response: {data}")
    # ---------------
    
    return JsonResponse(data)