from rest_framework import serializers

from main.models import Logger


class LogPostSerializer(serializers.ModelSerializer):
	class Meta:
		model = Logger
		fields = ['email', 'date', 'threshold', 'type_attack', 'command', 'if_warn',]
