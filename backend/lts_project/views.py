from django.http import JsonResponse

def health_check(request):
    """ALB Healthcheck Ep"""
    return JsonResponse({"status": "LTS Backend is Healthy!"})

def get_traffic_data(request):
    data = {
        "status": "success",
        "message": "Traffic data API endpoint reached!"
    }
    return JsonResponse(data)