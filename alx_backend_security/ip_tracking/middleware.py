from django.utils import timezone
from django.http import HttpResponseForbidden
from .models import RequestLog, BlockedIP

class IPLoggingMiddleware:
    """Middleware to log IP addresses and block blacklisted IPs."""
    
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Get the client's IP address
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        
        # Check if IP is blocked
        if BlockedIP.objects.filter(ip_address=ip).exists():
            return HttpResponseForbidden('Access denied: Your IP has been blocked')
        
        # Log the request details
        RequestLog.objects.create(
            ip_address=ip,
            path=request.path,
            timestamp=timezone.now()
        )
        
        response = self.get_response(request)
        return response