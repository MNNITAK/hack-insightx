/**
 * API Route: Self-Healing Operations
 * Handles CRUD operations for self-healing processes
 */

import { NextRequest, NextResponse } from 'next/server';
import { connectToDatabase } from '../../../lib/dbConnection';

// Import MongoDB models
const SelfHealing = require('../../../lib/models/SelfHealing');

/**
 * GET /api/healing - Get user's healing sessions
 * Query params: user_id, limit, offset, status, trigger_type
 */
export async function GET(request: NextRequest) {
  try {
    await connectToDatabase();
    
    const { searchParams } = new URL(request.url);
    const user_id = searchParams.get('user_id') || 'sample_user_123';
    const limit = parseInt(searchParams.get('limit') || '20');
    const offset = parseInt(searchParams.get('offset') || '0');
    const status = searchParams.get('status');
    const trigger_type = searchParams.get('trigger_type');
    
    let query: any = { user_id };
    if (status) {
      query.healing_status = status;
    }
    if (trigger_type) {
      query.trigger_type = trigger_type;
    }
    
    const healingSessions = await SelfHealing.find(query)
      .limit(limit)
      .skip(offset)
      .sort({ initiated_at: -1 });
    
    return NextResponse.json({
      success: true,
      data: healingSessions,
      count: healingSessions.length
    });
    
  } catch (error) {
    console.error('Error fetching healing sessions:', error);
    return NextResponse.json(
      { success: false, error: 'Failed to fetch healing sessions' },
      { status: 500 }
    );
  }
}

/**
 * POST /api/healing - Start new healing session
 */
export async function POST(request: NextRequest) {
  try {
    await connectToDatabase();
    
    const body = await request.json();
    const {
      user_id = 'sample_user_123',
      original_architecture,
      trigger_type = 'manual',
      trigger_id
    } = body;
    
    // Validate required fields
    if (!original_architecture) {
      return NextResponse.json(
        { success: false, error: 'Original architecture is required' },
        { status: 400 }
      );
    }
    
    // Create new healing session
    const healingSession = new SelfHealing({
      user_id,
      original_architecture,
      trigger_type,
      trigger_id,
      healing_status: 'initiated'
    });
    
    const savedHealing = await healingSession.save();
    
    return NextResponse.json({
      success: true,
      data: savedHealing,
      message: 'Healing session initiated successfully'
    });
    
  } catch (error) {
    console.error('Error starting healing session:', error);
    return NextResponse.json(
      { success: false, error: 'Failed to start healing session' },
      { status: 500 }
    );
  }
}

/**
 * PUT /api/healing - Update healing session
 */
export async function PUT(request: NextRequest) {
  try {
    await connectToDatabase();
    
    const body = await request.json();
    const {
      healing_session_id,
      user_id = 'sample_user_123',
      healing_status,
      detected_vulnerabilities,
      recommended_actions,
      healed_architecture,
      healing_assessment,
      user_decision,
      accepted_actions,
      rejected_actions,
      user_feedback
    } = body;
    
    if (!healing_session_id) {
      return NextResponse.json(
        { success: false, error: 'Healing session ID is required' },
        { status: 400 }
      );
    }
    
    // Find the healing session
    const healingSession = await SelfHealing.findOne({
      healing_session_id,
      user_id
    });
    
    if (!healingSession) {
      return NextResponse.json(
        { success: false, error: 'Healing session not found' },
        { status: 404 }
      );
    }
    
    // Update fields as provided
    if (healing_status) {
      healingSession.updateStatus(healing_status);
    }
    
    if (detected_vulnerabilities) {
      healingSession.detected_vulnerabilities = detected_vulnerabilities;
    }
    
    if (recommended_actions) {
      healingSession.recommended_actions = recommended_actions;
    }
    
    if (healed_architecture) {
      healingSession.healed_architecture = healed_architecture;
    }
    
    if (healing_assessment) {
      healingSession.healing_assessment = healing_assessment;
    }
    
    if (user_decision) {
      if (user_decision === 'accepted') {
        healingSession.acceptHealing(accepted_actions);
      } else if (user_decision === 'rejected') {
        healingSession.rejectHealing(rejected_actions, user_feedback);
      }
    }
    
    const updatedHealing = await healingSession.save();
    
    return NextResponse.json({
      success: true,
      data: updatedHealing,
      message: 'Healing session updated successfully'
    });
    
  } catch (error) {
    console.error('Error updating healing session:', error);
    return NextResponse.json(
      { success: false, error: 'Failed to update healing session' },
      { status: 500 }
    );
  }
}

/**
 * DELETE /api/healing - Delete healing session
 */
export async function DELETE(request: NextRequest) {
  try {
    await connectToDatabase();
    
    const { searchParams } = new URL(request.url);
    const healing_session_id = searchParams.get('healing_session_id');
    const user_id = searchParams.get('user_id') || 'sample_user_123';
    
    if (!healing_session_id) {
      return NextResponse.json(
        { success: false, error: 'Healing session ID is required' },
        { status: 400 }
      );
    }
    
    const result = await SelfHealing.deleteOne({
      healing_session_id,
      user_id
    });
    
    if (result.deletedCount === 0) {
      return NextResponse.json(
        { success: false, error: 'Healing session not found' },
        { status: 404 }
      );
    }
    
    return NextResponse.json({
      success: true,
      message: 'Healing session deleted successfully'
    });
    
  } catch (error) {
    console.error('Error deleting healing session:', error);
    return NextResponse.json(
      { success: false, error: 'Failed to delete healing session' },
      { status: 500 }
    );
  }
}