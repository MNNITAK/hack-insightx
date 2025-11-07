/**
 * API Route: Attack Simulations
 * Handles CRUD operations for attack simulation data
 */

import { NextRequest, NextResponse } from 'next/server';
import { connectToDatabase } from '../../../lib/dbConnection';

// Import MongoDB models
const AttackSimulation = require('../../../lib/models/AttackSimulation');

/**
 * GET /api/attacks - Get user's attack simulations
 * Query params: user_id, limit, offset, status
 */
export async function GET(request: NextRequest) {
  try {
    await connectToDatabase();
    
    const { searchParams } = new URL(request.url);
    const user_id = searchParams.get('user_id') || 'sample_user_123';
    const limit = parseInt(searchParams.get('limit') || '20');
    const offset = parseInt(searchParams.get('offset') || '0');
    const status = searchParams.get('status');
    
    let query: any = { user_id };
    if (status) {
      query.attack_status = status;
    }
    
    const attacks = await AttackSimulation.find(query)
      .limit(limit)
      .skip(offset)
      .sort({ initiated_at: -1 });
    
    return NextResponse.json({
      success: true,
      data: attacks,
      count: attacks.length
    });
    
  } catch (error) {
    console.error('Error fetching attacks:', error);
    return NextResponse.json(
      { success: false, error: 'Failed to fetch attacks' },
      { status: 500 }
    );
  }
}

/**
 * POST /api/attacks - Save new attack simulation
 */
export async function POST(request: NextRequest) {
  try {
    await connectToDatabase();
    
    const body = await request.json();
    const {
      user_id = 'sample_user_123',
      configured_attack,
      target_architecture,
      attack_configuration
    } = body;
    
    // Validate required fields
    if (!configured_attack || !target_architecture) {
      return NextResponse.json(
        { success: false, error: 'Attack configuration and target architecture are required' },
        { status: 400 }
      );
    }
    
    // Create new attack simulation document
    const attackSimulation = new AttackSimulation({
      user_id,
      configured_attack,
      target_architecture,
      attack_configuration: attack_configuration || {},
      attack_status: 'initiated'
    });
    
    const savedAttack = await attackSimulation.save();
    
    return NextResponse.json({
      success: true,
      data: savedAttack,
      message: 'Attack simulation saved successfully'
    });
    
  } catch (error) {
    console.error('Error saving attack:', error);
    return NextResponse.json(
      { success: false, error: 'Failed to save attack simulation' },
      { status: 500 }
    );
  }
}

/**
 * PUT /api/attacks - Update attack simulation status
 */
export async function PUT(request: NextRequest) {
  try {
    await connectToDatabase();
    
    const body = await request.json();
    const {
      attack_session_id,
      user_id = 'sample_user_123',
      attack_status,
      validation_result,
      suggested_architecture,
      user_decision
    } = body;
    
    if (!attack_session_id) {
      return NextResponse.json(
        { success: false, error: 'Attack session ID is required' },
        { status: 400 }
      );
    }
    
    // Find the attack simulation
    const attackSimulation = await AttackSimulation.findOne({
      attack_session_id,
      user_id
    });
    
    if (!attackSimulation) {
      return NextResponse.json(
        { success: false, error: 'Attack simulation not found' },
        { status: 404 }
      );
    }
    
    // Update fields as provided
    if (attack_status) {
      attackSimulation.updateStatus(attack_status);
    }
    
    if (validation_result) {
      attackSimulation.validation_result = validation_result;
    }
    
    if (suggested_architecture) {
      attackSimulation.suggested_architecture = suggested_architecture;
    }
    
    if (user_decision) {
      if (user_decision === 'accepted') {
        attackSimulation.acceptSuggestion();
      } else if (user_decision === 'rejected') {
        attackSimulation.rejectSuggestion(body.rejection_reason || 'No reason provided');
      }
    }
    
    const updatedAttack = await attackSimulation.save();
    
    return NextResponse.json({
      success: true,
      data: updatedAttack,
      message: 'Attack simulation updated successfully'
    });
    
  } catch (error) {
    console.error('Error updating attack:', error);
    return NextResponse.json(
      { success: false, error: 'Failed to update attack simulation' },
      { status: 500 }
    );
  }
}

/**
 * DELETE /api/attacks - Delete attack simulation
 */
export async function DELETE(request: NextRequest) {
  try {
    await connectToDatabase();
    
    const { searchParams } = new URL(request.url);
    const attack_session_id = searchParams.get('attack_session_id');
    const user_id = searchParams.get('user_id') || 'sample_user_123';
    
    if (!attack_session_id) {
      return NextResponse.json(
        { success: false, error: 'Attack session ID is required' },
        { status: 400 }
      );
    }
    
    const result = await AttackSimulation.deleteOne({
      attack_session_id,
      user_id
    });
    
    if (result.deletedCount === 0) {
      return NextResponse.json(
        { success: false, error: 'Attack simulation not found' },
        { status: 404 }
      );
    }
    
    return NextResponse.json({
      success: true,
      message: 'Attack simulation deleted successfully'
    });
    
  } catch (error) {
    console.error('Error deleting attack:', error);
    return NextResponse.json(
      { success: false, error: 'Failed to delete attack simulation' },
      { status: 500 }
    );
  }
}